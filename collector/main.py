import os
import logging
import json
import re
import httpx
import asyncio
import sys
import yaml
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from dotenv import load_dotenv
import base64
import binascii

load_dotenv()

BASE_URL = os.getenv("BASE_URL")
LOKI_URL = f"{BASE_URL}/api/datasources/proxy/uid/loki"
TEMPO_URL = f"{BASE_URL}/api/datasources/proxy/uid/tempo"
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DeepDiveCollector")

@dataclass
class TriggerRequest:
    """提取的 HTTP 請求信息"""
    method: Optional[str] = None
    endpoint: Optional[str] = None
    query_params: Optional[Dict[str, str]] = None
    duration_ms: Optional[float] = None

@dataclass
class TimelineEvent:
    """時間軸上的一個事件"""
    time_offset_ms: float
    event_type: str
    name: str
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Incident:
    trace_id: str
    timestamp: datetime
    error_log: str
    context_logs: List[Dict] = field(default_factory=list)
    trace_logs: List[Dict] = field(default_factory=list)
    trace_detail: Optional[Dict] = None
    trigger_request: Optional[TriggerRequest] = None
    timeline: List[str] = field(default_factory=list)
    context_requests: List[str] = field(default_factory=list)

# --- 工具函數 ---
def load_config(config_path: str) -> Dict[str, Any]:
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Config load error: {e}")
        sys.exit(1)

def parse_time(time_str: str) -> datetime:
    return datetime.fromisoformat(time_str.replace('Z', '+00:00'))

def normalize_id(id_val: str) -> str:
    """
    統一將 ID 轉換為小寫 Hex 格式。
    能夠自動識別並處理 Base64 編碼的 Trace/Span ID。
    """
    if not id_val:
        return ""
    
    s = str(id_val).strip()
    
    # 判斷是否為 Base64 格式
    # SpanID (8 bytes) Base64 後長度通常是 12 (含 padding)
    # TraceID (16 bytes) Base64 後長度通常是 24 (含 padding)
    if len(s) in [12, 24] and (s.endswith('=') or '+' in s or '/' in s):
        try:
            # 嘗試 Base64 解碼並轉為 Hex
            decoded_bytes = base64.b64decode(s)
            return decoded_bytes.hex().lower()
        except (binascii.Error, ValueError):
            # 如果解碼失敗，就當作它是普通的字串處理
            pass
            
    # 如果不是 Base64，假設它已經是 Hex，直接轉小寫
    return s.lower()

def extract_trace_id(log: str) -> Optional[str]:
    try:
        log_json = json.loads(log)
        if isinstance(log_json, dict):
            for key in ['trace_id']:
                if key in log_json:
                    trace_id = log_json[key]
                    if trace_id and isinstance(trace_id, str) and len(trace_id) in [16, 32]:
                        return trace_id
    except (json.JSONDecodeError, ValueError):
        pass
    
    patterns = [
        r'"trace_id"\s*:\s*"([a-f0-9]{32}|[a-f0-9]{16})"',
        r'"traceID"\s*:\s*"([a-f0-9]{32}|[a-f0-9]{16})"',
        r'(?:traceID|trace_id|trace-id)\s*[=:]\s*["\']?([a-f0-9]{32}|[a-f0-9]{16})["\']?',
        r'\[([a-f0-9]{32}|[a-f0-9]{16})\]',
        r'(?:^|[\s,])([a-f0-9]{32})(?:[\s,]|$)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, log, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None

def extract_span_id(log: str) -> Optional[str]:
    """從日誌內容中提取 Span ID (通常是 16 碼 Hex)"""
    # 優先嘗試 JSON 解析
    try:
        log_json = json.loads(log)
        if isinstance(log_json, dict):
            for key in ['span_id', 'spanID', 'span-id']:
                if key in log_json:
                    span_id = log_json[key]
                    if span_id and isinstance(span_id, str) and len(span_id) == 16:
                        return span_id
    except (json.JSONDecodeError, ValueError):
        pass
    
    # Fallback: Regex 提取
    patterns = [
        r'"span_id"\s*:\s*"([a-f0-9]{16})"',
        r'"spanID"\s*:\s*"([a-f0-9]{16})"',
        r'(?:spanID|span_id|span-id)\s*[=:]\s*["\']?([a-f0-9]{16})["\']?',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, log, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None

def extract_timestamp_from_loki_result(value_pair: List) -> datetime:
    ns_timestamp = int(value_pair[0])
    return datetime.fromtimestamp(ns_timestamp / 1e9).astimezone()

def get_auth_headers() -> Dict[str, str]:
    if AUTH_TOKEN:
        return {"Authorization": f"Bearer {AUTH_TOKEN}"}
    return {}

def simplify_trace_for_llm(trace_data: Dict, external_logs: List[Dict] = None) -> str:
    """
    將 OTLP JSON Trace 轉換為 LLM 易讀的 YAML 格式字串，
    並將 external_logs (Loki Logs) 分配到對應的 Span 中。
    """
    if not trace_data or "batches" not in trace_data:
        return "No trace data available."

    span_map = {}
    children_map = {}
    all_spans = []
    min_start_time = float('inf')

    # --- 步驟 A: 預處理外部 Logs，建立 Span ID -> Logs 的索引 ---
    logs_by_span = {}
    unmatched_logs = []  # 新增：無 Span ID 的日誌
    
    if external_logs:
        for log_entry in external_logs:
            # 取得 log 內容字串
            raw_log = log_entry.get("log", log_entry.get("message", ""))
            if not isinstance(raw_log, str):
                raw_log = str(raw_log)
            
            # 嘗試提取 Span ID
            sid = extract_span_id(raw_log)
            clean_msg = filter_log_fields(raw_log)
            ts_str = str(log_entry.get("timestamp", ""))
            
            if sid:
                # 有 Span ID：關聯到特定 Span
                if sid not in logs_by_span:
                    logs_by_span[sid] = []
                logs_by_span[sid].append({"ts": ts_str, "msg": clean_msg})
            else:
                # 無 Span ID：收集為 unmatched
                unmatched_logs.append({"ts": ts_str, "msg": clean_msg})

    # --- 步驟 B: 解析 Trace ---
    for batch in trace_data.get("batches", []):
        for scope_span in batch.get("scopeSpans", []):
            scope_name = scope_span.get("scope", {}).get("name", "unknown")
            for span in scope_span.get("spans", []):
                span_id = span["spanId"]
                parent_id = span.get("parentSpanId")
                start_ns = int(span.get("startTimeUnixNano", 0))
                end_ns = int(span.get("endTimeUnixNano", 0))
                
                if start_ns > 0 and start_ns < min_start_time:
                    min_start_time = start_ns
                
                span_data = {
                    "id": span_id,
                    "parent_id": parent_id,
                    "name": span["name"],
                    "scope": scope_name,
                    "start_ns": start_ns,
                    "end_ns": end_ns,
                    "attributes": span.get("attributes", []),
                    "events": span.get("events", []), # 這是 Trace 原生的 Events
                    "status": span.get("status", {})
                }
                span_map[span_id] = span_data
                all_spans.append(span_data)
                
                if parent_id:
                    if parent_id not in children_map:
                        children_map[parent_id] = []
                    children_map[parent_id].append(span_id)

    if min_start_time == float('inf'):
        min_start_time = 0

    roots = []
    for span in all_spans:
        if not span["parent_id"] or span["parent_id"] not in span_map:
            roots.append(span["id"])

    # --- 步驟 C: 遞迴建構樹，並注入 Logs ---
    def build_node(span_id):
        span = span_map[span_id]
        duration_ms = (span["end_ns"] - span["start_ns"]) / 1e6 if span["end_ns"] else 0
        start_offset_ms = (span["start_ns"] - min_start_time) / 1e6 if span["start_ns"] else 0
        
        node = {
            "span": span["name"],
            "module": span["scope"],
            "time": f"+{start_offset_ms:.2f}ms",
            "duration": f"{duration_ms:.2f}ms",
        }

        # Attributes
        attrs = {}
        for attr in span["attributes"]:
            key = attr["key"]
            val = attr["value"].get("stringValue") or attr["value"].get("intValue") or attr["value"].get("boolValue") or str(attr["value"])
            if key in ["method", "path", "db.statement", "http.status_code", "component", "peer.service"]:
                attrs[key] = val
        if attrs:
            node["details"] = attrs

        # Error handling from Trace Status
        status_code = span["status"].get("code")
        if status_code == 2 or status_code == "STATUS_CODE_ERROR":
             node["status"] = "FAILED"

        # --- [重點修改] 合併 Trace Events 與 External Logs ---
        combined_logs = []

        # 1. 加入 Trace 內建 Events (例如 exception)
        for event in span["events"]:
            event_attributes = event.get("attributes", [])
            
            if event["name"] == "exception":
                ex_details = {}
                for attr in event_attributes:
                    k = attr["key"].replace("exception.", "")
                    v = attr["value"].get("stringValue", str(attr["value"]))
                    ex_details[k] = v
                node["error"] = ex_details
                node["status"] = "FAILED"
            else:
                # 其他 Trace Events
                e_msg = event["name"]
                for attr in event_attributes:
                     if attr["key"] == "message": e_msg += f" - {attr['value'].get('stringValue')}"
                combined_logs.append(f"[TraceEvent] {e_msg}")

        # 2. 加入 External Logs (從 Loki 來的，有 Span ID 的)
        span_id_hex = normalize_id(span_id)
        if span_id_hex in logs_by_span:
            for l in logs_by_span[span_id_hex]:
                combined_logs.append(f"[Log@{l['ts']}] {l['msg']}")
        
        if combined_logs:
            node["logs"] = combined_logs

        # 遞迴子節點
        children = children_map.get(span_id, [])
        children.sort(key=lambda cid: span_map[cid]["start_ns"])
        
        if children:
            node["children"] = [build_node(cid) for cid in children]
            
        return node

    simplified_tree = [build_node(root_id) for root_id in roots]
    
    # --- 步驟 D: 將無法匹配 Span ID 的日誌附加在最後 ---
    if unmatched_logs:
        # 按時間排序
        unmatched_logs.sort(key=lambda x: x['ts'])
        unmatched_section = {
            "unmatched_logs": [f"[{log['ts']}] {log['msg']}" for log in unmatched_logs]
        }
        simplified_tree.append(unmatched_section)
    
    return yaml.dump(simplified_tree, allow_unicode=True, sort_keys=False, default_flow_style=False)

# --- Trace Parser 工具 ---

def find_root_span(trace_data: Dict) -> Optional[Dict]:
    if not trace_data or "batches" not in trace_data:
        return None
    for batch in trace_data.get("batches", []):
        for span_set in batch.get("scopeSpans", []):
            for span in span_set.get("spans", []):
                parent_id = span.get("parentSpanId", "")
                if not parent_id or parent_id == "":
                    return span
    return None

def find_next_span(trace_data: Dict, parent_span: Dict) -> Optional[Dict]:
    if not trace_data or "batches" not in trace_data or not parent_span:
        return None
    parent_span_id = parent_span.get("spanId", "")
    if not parent_span_id:
        return None
    for batch in trace_data.get("batches", []):
        for span_set in batch.get("scopeSpans", []):
            for span in span_set.get("spans", []):
                parent_id = span.get("parentSpanId", "")
                if parent_id == parent_span_id:
                    return span
    return None

def extract_trigger_request(root_span: Dict, next_span: Optional[Dict] = None) -> TriggerRequest:
    trigger_req = TriggerRequest()
    span_to_extract = next_span if next_span else root_span
    if not span_to_extract:
        return trigger_req
    
    attributes = span_to_extract.get("attributes", [])
    attr_dict = {}
    for attr in attributes:
        if "key" in attr and "value" in attr:
            key = attr["key"]
            value = attr["value"]
            if "stringValue" in value:
                attr_dict[key] = value["stringValue"]
            elif "intValue" in value:
                attr_dict[key] = value["intValue"]
            elif "doubleValue" in value:
                attr_dict[key] = value["doubleValue"]
            elif "boolValue" in value:
                attr_dict[key] = value["boolValue"]
    
    trigger_req.method = attr_dict.get("method", attr_dict.get("http.method"))
    trigger_req.endpoint = attr_dict.get("path", attr_dict.get("http.target", attr_dict.get("http.url")))
    trigger_req.query_params = attr_dict.get("query")
    
    start_time_ns = int(root_span.get("startTimeUnixNano", 0))
    end_time_ns = int(root_span.get("endTimeUnixNano", 0))
    if start_time_ns and end_time_ns:
        trigger_req.duration_ms = (end_time_ns - start_time_ns) / 1e6
    
    span_source = "next_span" if next_span else "root_span"
    logger.info(f"[Trigger] Source: {span_source}, Method: {trigger_req.method}, Endpoint: {trigger_req.endpoint}")
    return trigger_req

def filter_log_fields(log_str: str) -> str:
    try:
        log_json = json.loads(log_str)
        if isinstance(log_json, dict):
            important_fields = ["ts", "level", "caller", "msg", "trace_id", "span_id", "error", "message"]
            filtered = {k: v for k, v in log_json.items() if k in important_fields}
            return json.dumps(filtered, ensure_ascii=False)
    except (json.JSONDecodeError, ValueError):
        pass
    return log_str

def build_timeline_from_trace_and_logs(trace_data: Dict, context_logs: List[Dict], trace_logs: List[Dict], root_span_start_ns: int) -> List[str]:
    collected: List[tuple[int, str]] = []
    
    # 用來去重的集合：儲存已處理過的 Log 簽章 (timestamp_ns, raw_log_content)
    seen_logs = set()

    # --- 1. 優先處理 Trace Logs (相同 trace ID 的日誌) ---
    # 策略：這些是我們最確定的關聯日誌，優先保留並標記為 TRACE_ID_LOG
    for log_entry in trace_logs:
        if isinstance(log_entry, dict) and "timestamp" in log_entry:
            ts_ns = int(log_entry["timestamp"].timestamp() * 1e9)
            raw_log = log_entry.get("log", log_entry.get("message", ""))
            
            # 建立唯一簽章 (Signature)
            # 使用 str(raw_log) 確保內容被當作字串比對
            signature = (ts_ns, str(raw_log))
            
            if signature not in seen_logs:
                seen_logs.add(signature)
                message = raw_log if isinstance(raw_log, str) else extract_log_message(raw_log)
                filtered_message = filter_log_fields(message)
                collected.append((ts_ns, f"TRACE_ID_LOG: {filtered_message}"))

    # --- 2. 處理 Context Logs (前後日誌) ---
    # 策略：如果這條 Log 已經在上面出現過 (即屬於該 Trace ID)，則跳過不加，避免重複
    for log_entry in context_logs:
        if isinstance(log_entry, dict) and "timestamp" in log_entry:
            ts_ns = int(log_entry["timestamp"].timestamp() * 1e9)
            raw_log = log_entry.get("log", log_entry.get("message", ""))
            
            signature = (ts_ns, str(raw_log))
            
            # [關鍵修改] 去重檢查：如果已經在 trace_logs 裡處理過，就跳過
            if signature in seen_logs:
                continue
            
            # 只有當它是新的 Log 時才加入
            seen_logs.add(signature) # 雖然這之後不會再用到，但保持一致性
            message = raw_log if isinstance(raw_log, str) else extract_log_message(raw_log)
            filtered_message = filter_log_fields(message)
            collected.append((ts_ns, f"LOKI_LOG: {filtered_message}"))

    # --- 3. 處理 Trace events (來自 Tempo 的 Span 事件) ---
    if trace_data and "batches" in trace_data:
        for batch in trace_data.get("batches", []):
            for span_set in batch.get("scopeSpans", []):
                for span in span_set.get("spans", []):
                    span_start = int(span.get("startTimeUnixNano", 0))
                    offset_ms = (span_start - root_span_start_ns) / 1e6 if root_span_start_ns else 0
                    
                    # Add span start event
                    collected.append((span_start, f"[+{offset_ms:.2f}ms] SPAN: {span.get('name')}"))

                    for event in span.get("events", []):
                        ts_ns = int(event.get("timeUnixNano", 0))
                        message = None
                        for attr in event.get("attributes", []):
                            if "key" in attr and "value" in attr and attr["key"] in ["log.message", "message", "msg", "log", "exception.message"]:
                                val = attr["value"]
                                if "stringValue" in val:
                                    message = val["stringValue"]
                                break
                        if message:
                            collected.append((ts_ns, f"TRACE_EVENT: {message}"))

    collected.sort(key=lambda x: x[0])
    return [msg for _, msg in collected]

def extract_log_message(log_content: Any) -> str:
    candidate_keys = ["log.message", "message", "msg", "log"]
    if isinstance(log_content, dict):
        for key in candidate_keys:
            val = log_content.get(key)
            if isinstance(val, str):
                return val
        return str(log_content)
    if isinstance(log_content, str):
        try:
            parsed = json.loads(log_content)
            if isinstance(parsed, dict):
                for key in candidate_keys:
                    val = parsed.get(key)
                    if isinstance(val, str):
                        return val
        except (json.JSONDecodeError, ValueError):
            pass
        return log_content
    return str(log_content)

# --- LogQL 組裝工具 ---
def build_logql_and_params(start: datetime, end: datetime, limit: int, labels: Dict[str, Any], regex_filter: Optional[str], direction: str) ->  Dict[str, Any]:
    labels = dict(labels)
    label_parts = []
    for k, v in labels.items():
        if isinstance(v, list):
            values_regex = "|".join(v)
            label_parts.append(f'{k}=~"{values_regex}"')
        else:
            label_parts.append(f'{k}="{v}"')
    label_selector = "{" + ", ".join(label_parts) + "}"
    
    if regex_filter:
        logql = f'{label_selector} |~ "(?i){regex_filter}"'
    else:
        logql = label_selector
    
    start_ns = int(start.timestamp() * 1e9)
    end_ns = int(end.timestamp() * 1e9)
    params = {"query": logql, "start": start_ns, "end": end_ns, "limit": limit, "direction": direction}
    return params

# --- 核心邏輯 ---
async def scan_for_errors(client: httpx.AsyncClient, labels: Dict[str, Any], start: datetime, end: datetime, regex_filter: str) -> List[tuple]:
    labels["level"] = ["warn", "error", "fatal"]
    params = build_logql_and_params(start, end, 1000, labels, regex_filter, "backward")
    try:
        resp = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, headers=get_auth_headers())
        resp.raise_for_status()
        data = resp.json()
        found_events = []
        if "data" in data and "result" in data["data"]:
            for stream in data["data"]["result"]:
                for values in stream["values"]:
                    ts = extract_timestamp_from_loki_result(values)
                    log_content = values[1]
                    tid = extract_trace_id(log_content)
                    if tid:
                        found_events.append((ts, log_content, tid))
        return found_events
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return []

async def fetch_incident_context(client: httpx.AsyncClient, incident: Incident, labels: Dict[str, str], window_sec: int):
    center_ts = incident.timestamp
    start_ts = center_ts - timedelta(seconds=window_sec)
    end_ts = center_ts
    ctx_labels = dict(labels)
    # ctx_labels["level"] = ["error", "warn", "fatal"]
    params = build_logql_and_params(start_ts, end_ts, 500, ctx_labels, None, "forward")
    try:
        resp = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, headers=get_auth_headers())
        if resp.status_code == 200:
            data = resp.json()
            logs = []
            if "data" in data and "result" in data["data"]:
                for stream in data["data"]["result"]:
                    for values in stream["values"]:
                        ts = extract_timestamp_from_loki_result(values)
                        log_content = values[1]
                        trace_id = extract_trace_id(log_content)
                        logs.append({"timestamp": ts, "log": log_content, "trace_id": trace_id, "level": "error"})
            incident.context_logs = logs
    except Exception as e:
        logger.error(f"Context fetch failed for {incident.trace_id}: {e}")

async def fetch_tempo_trace(client: httpx.AsyncClient, incident: Incident):
    try:
        resp = await client.get(f"{TEMPO_URL}/api/traces/{incident.trace_id}", headers=get_auth_headers())
        if resp.status_code == 200:
            incident.trace_detail = resp.json()
            root_span = find_root_span(incident.trace_detail)
            if root_span:
                next_span = find_next_span(incident.trace_detail, root_span)
                incident.trigger_request = extract_trigger_request(root_span, next_span)
                root_span_start_ns = int(root_span.get("startTimeUnixNano", 0))
                incident.timeline = build_timeline_from_trace_and_logs(incident.trace_detail, incident.context_logs, incident.trace_logs, root_span_start_ns)
        elif resp.status_code == 404:
            logger.warning(f"Trace {incident.trace_id} not found in Tempo.")
    except Exception as e:
        logger.error(f"Tempo fetch failed for {incident.trace_id}: {e}")

async def fetch_logs_by_trace_id(client: httpx.AsyncClient, incident: Incident, labels: Dict[str, str]):
    """
    基於 Trace ID 向 Loki 查詢所有相關日誌。
    搜尋範圍預設為 Incident 時間的前後 5 分鐘，確保包含整個 Trace。
    """
    center_ts = incident.timestamp
    # 給予較寬的時間窗口 (例如前後 5 分鐘)，以免 Trace 執行很久被切斷
    start_ts = center_ts - timedelta(minutes=5)
    end_ts = center_ts + timedelta(minutes=5)
    
    # 建構 LogQL: {labels} |= "trace_id"
    # 這會過濾出所有包含該 Trace ID 字串的 Log
    label_parts = []
    for k, v in labels.items():
        if isinstance(v, list):
            values_regex = "|".join(v)
            label_parts.append(f'{k}=~"{values_regex}"')
        else:
            label_parts.append(f'{k}="{v}"')
    
    label_selector = "{" + ", ".join(label_parts) + "}"
    
    # 關鍵 LogQL：使用 |= 進行精確字串匹配
    logql = f'{label_selector} |= "{incident.trace_id}"'
    
    start_ns = int(start_ts.timestamp() * 1e9)
    end_ns = int(end_ts.timestamp() * 1e9)
    
    params = {
        "query": logql, 
        "start": start_ns, 
        "end": end_ns, 
        "limit": 5000, # 盡量抓多一點
        "direction": "backward"
    }

    try:
        resp = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, headers=get_auth_headers())
        if resp.status_code == 200:
            data = resp.json()
            logs = []
            if "data" in data and "result" in data["data"]:
                for stream in data["data"]["result"]:
                    for values in stream["values"]:
                        ts = extract_timestamp_from_loki_result(values)
                        log_content = values[1]
                        # 這裡我們不需要再過濾 level，只要有 Trace ID 就都要
                        logs.append({
                            "timestamp": ts, 
                            "log": log_content, 
                            "trace_id": incident.trace_id, 
                            "source": "trace_id_match" # 標記來源
                        })
            incident.trace_logs = logs
            logger.info(f"Fetched {len(logs)} logs for trace {incident.trace_id}")
    except Exception as e:
        logger.error(f"Trace ID log fetch failed for {incident.trace_id}: {e}")

async def fetch_context_requests(client: httpx.AsyncClient, incident: Incident, labels: Dict[str, str], window_sec: int):
    center_ts = incident.timestamp
    start_ts = center_ts - timedelta(seconds=window_sec)
    end_ts = center_ts
    ctx_labels = dict(labels)
    if "level" in ctx_labels: del ctx_labels["level"]
    params = build_logql_and_params(start_ts, end_ts, 1000, ctx_labels, None, "forward")
    trace_info = {}
    try:
        resp = await client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params, headers=get_auth_headers())
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "result" in data["data"]:
                for stream in data["data"]["result"]:
                    for values in stream["values"]:
                        ts = extract_timestamp_from_loki_result(values)
                        log_content = values[1]
                        tid = extract_trace_id(log_content)
                        if tid and tid != incident.trace_id and tid not in trace_info:
                            trace_info[tid] = ts
        
        context_requests = []
        for tid, ts in list(trace_info.items())[:50]:
            try:
                trace_resp = await client.get(f"{TEMPO_URL}/api/traces/{tid}", headers=get_auth_headers())
                if trace_resp.status_code == 200:
                    trace_data = trace_resp.json()
                    root_span = find_root_span(trace_data)
                    if root_span:
                        next_span = find_next_span(trace_data, root_span)
                        span_to_extract = next_span if next_span else root_span
                        if span_to_extract:
                            attr_dict = {a["key"]: a["value"].get("stringValue", "") for a in span_to_extract.get("attributes", []) if "key" in a and "value" in a}
                            method = attr_dict.get("method", attr_dict.get("http.method"))
                            endpoint = attr_dict.get("path", attr_dict.get("http.target"))
                            query = attr_dict.get("query")
                            if method and endpoint:
                                req = f"{ts.isoformat()} {method} {endpoint}"
                                if query: req += f"?{query}"
                                context_requests.append(req)
            except Exception:
                continue
        incident.context_requests = context_requests
    except Exception as e:
        logger.error(f"Context requests fetch failed for {incident.trace_id}: {e}")

async def process_incident(client: httpx.AsyncClient, incident: Incident, labels: Dict, window: int):
    await asyncio.gather(
        fetch_incident_context(client, incident, labels, window),
        fetch_logs_by_trace_id(client, incident, labels),
        fetch_tempo_trace(client, incident),
        fetch_context_requests(client, incident, labels, window)
    )
    return incident

async def main():
    config = load_config("config.json")
    labels = config.get("labels", {})
    scan_settings = config.get("scan_settings", {})
    start_time = parse_time(config["time_range"]["start"])
    end_time = parse_time(config["time_range"]["end"])
    max_concurrent_tasks = scan_settings.get("max_concurrent_tasks", 5)
    context_window_sec = scan_settings.get("context_window_seconds", 1)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        raw_events = await scan_for_errors(client, labels, start_time, end_time, None)
        unique_incidents = {}
        for ts, content, tid in raw_events:
            unique_incidents[tid] = Incident(trace_id=tid, timestamp=ts, error_log=content)
        
        logger.info(f"[Phase 1] Identified {len(unique_incidents)} unique incidents.")
        
        tasks = []
        semaphore = asyncio.Semaphore(max_concurrent_tasks)
        filtered_incidents = []
        for inc in unique_incidents.values():
            should_fetch = True
            for existing_inc in filtered_incidents:
                if existing_inc.timestamp - timedelta(seconds=context_window_sec) <= inc.timestamp <= existing_inc.timestamp:
                    should_fetch = False
                    break
            if should_fetch: filtered_incidents.append(inc)

        async def sem_task(inc):
            async with semaphore: return await process_incident(client, inc, labels, context_window_sec)

        for incident in filtered_incidents:
            tasks.append(sem_task(incident))
        
        enriched_incidents = await asyncio.gather(*tasks) if tasks else []
        logger.info(f"[Phase 2] Processed {len(enriched_incidents)} incidents.")

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = f"incident_report_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    
    with open(os.path.join(output_dir, "meta.json"), 'w', encoding='utf-8') as f:
        json.dump({
            "task": config.get("task_name"),
            "scan_range": f"{start_time} - {end_time}",
            "total_incidents": len(enriched_incidents),
            "generated_at": timestamp
        }, f, indent=2, ensure_ascii=False)
    
    for idx, inc in enumerate(enriched_incidents, 1):
        trigger_req_data = None
        if inc.trigger_request:
            trigger_req_data = {
                "method": inc.trigger_request.method,
                "endpoint": inc.trigger_request.endpoint,
                "query_params": inc.trigger_request.query_params,
                "duration_ms": inc.trigger_request.duration_ms,
            }
        
        serializable_context_logs = []
        for log in inc.context_logs:
            sl = dict(log)
            if "timestamp" in sl and isinstance(sl["timestamp"], datetime): sl["timestamp"] = str(sl["timestamp"])
            serializable_context_logs.append(sl)
        
        # --- [修改] 3. 使用 simplify_trace_for_llm 轉換格式 ---
        llm_trace_view = simplify_trace_for_llm(
            inc.trace_detail,
            inc.trace_logs)
        
        incident_data = {
            "incident_summary": {
                "trace_id": inc.trace_id,
                "timestamp": str(inc.timestamp),
                "service_name": config.get("labels", {}).get("service_name", "unknown"),
                "error_log": filter_log_fields(inc.error_log)
            },
            "trigger_request": trigger_req_data,
            "context_requests": inc.context_requests,
            "timeline": inc.timeline,
            "trace_dump": llm_trace_view,
            # "raw_trace": inc.trace_detail # 如果需要保留原始 JSON 可解開此行
        }
        
        trace_id_short = inc.trace_id[:8]
        filename_full = f"incident_{idx:04d}_{trace_id_short}.json"
        with open(os.path.join(output_dir, filename_full), 'w', encoding='utf-8') as f:
            json.dump(incident_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Report generated in directory: {output_dir}/")

if __name__ == "__main__":
    asyncio.run(main())