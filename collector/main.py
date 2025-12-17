import os
import logging
import json
import re
import httpx
import asyncio
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- 配置設定 ---
# 預設連線位置，可透過環境變數覆蓋
BASE_URL = os.getenv("BASE_URL")
LOKI_URL = f"{BASE_URL}/api/datasources/proxy/uid/loki"
TEMPO_URL = f"{BASE_URL}/api/datasources/proxy/uid/tempo"
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("DeepDiveCollector")

# --- 資料結構 ---
@dataclass
class TriggerRequest:
    """提取的 HTTP 請求信息"""
    method: Optional[str] = None
    endpoint: Optional[str] = None
    query_params: Optional[Dict[str, str]] = None
    duration_ms: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TimelineEvent:
    """時間軸上的一個事件"""
    time_offset_ms: float
    event_type: str  # "span_start", "span_end", "log", "exception", "span_call"
    name: str
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Incident:
    trace_id: str
    timestamp: datetime
    error_log: str
    context_logs: List[Dict] = field(default_factory=list)
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
    """解析 ISO 8601 時間字串"""
    # 處理 UTC 'Z'，Python 3.11+ 原生支援 fromisoformat 讀取 Z，這裡做相容處理
    return datetime.fromisoformat(time_str.replace('Z', '+00:00'))

def extract_trace_id(log: str) -> Optional[str]:
    """從日誌內容中提取 Trace ID"""
    # 首先嘗試 JSON 解析（優先處理 JSON 格式的 log）
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
    
    # Fallback：使用 regex 從非 JSON 格式或嵌入的 JSON 字符串中提取
    patterns = [
        r'"trace_id"\s*:\s*"([a-f0-9]{32}|[a-f0-9]{16})"',  # JSON format
        r'"traceID"\s*:\s*"([a-f0-9]{32}|[a-f0-9]{16})"',  # JSON format (camelCase)
        r'(?:traceID|trace_id|trace-id)\s*[=:]\s*["\']?([a-f0-9]{32}|[a-f0-9]{16})["\']?',  # key=value format
        r'\[([a-f0-9]{32}|[a-f0-9]{16})\]',  # [trace_id] format
        r'(?:^|[\s,])([a-f0-9]{32})(?:[\s,]|$)',  # 32-char hex anywhere
    ]
    
    for pattern in patterns:
        match = re.search(pattern, log, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None

def extract_timestamp_from_loki_result(value_pair: List) -> datetime:
    """從 Loki 回傳的 [ns_epoch, line] 格式中解析時間"""
    ns_timestamp = int(value_pair[0])
    # 轉為 datetime 物件
    return datetime.fromtimestamp(ns_timestamp / 1e9).astimezone()

def get_auth_headers() -> Dict[str, str]:
    """Get authentication headers"""
    if AUTH_TOKEN:
        return {"Authorization": f"Bearer {AUTH_TOKEN}"}
    return {}

# --- Trace Parser 工具 (修改建議 A: 解析 Root Span) ---

def find_root_span(trace_data: Dict) -> Optional[Dict]:
    """
    從 Tempo 的原始 Trace 中找出 Root Span
    Root Span 通常是沒有 parentSpanId 或 parentSpanId 為空的 Span
    """
    if not trace_data or "batches" not in trace_data:
        return None
    
    for batch in trace_data.get("batches", []):
        for span_set in batch.get("scopeSpans", []):
            for span in span_set.get("spans", []):
                parent_id = span.get("parentSpanId", "")
                # Root Span 的特徵：沒有 parent 或 parent 為空
                if not parent_id or parent_id == "":
                    return span
    
    return None

def find_next_span(trace_data: Dict, parent_span: Dict) -> Optional[Dict]:
    """
    找出 Parent Span 的下一個子 Span
    """
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
    """
    從 Parent Span 的下一個子 Span 提取 HTTP 請求資訊
    修改建議 A: 解析 Tempo Root Span 的下一個 Span 獲取 Request Info
    """
    trigger_req = TriggerRequest()
    
    # 優先從 next_span 提取，如果沒有則回退到 root_span
    span_to_extract = next_span if next_span else root_span
    
    if not span_to_extract:
        return trigger_req
    
    # 從 attributes 中提取 HTTP 相關欄位
    attributes = span_to_extract.get("attributes", [])
    
    # 將 attributes 列表轉換為字典便於查詢
    attr_dict = {}
    for attr in attributes:
        if "key" in attr and "value" in attr:
            key = attr["key"]
            value = attr["value"]
            # 解析 OpenTelemetry AnyValue 格式
            if "stringValue" in value:
                attr_dict[key] = value["stringValue"]
            elif "intValue" in value:
                attr_dict[key] = value["intValue"]
            elif "doubleValue" in value:
                attr_dict[key] = value["doubleValue"]
            elif "boolValue" in value:
                attr_dict[key] = value["boolValue"]
    
    trigger_req.method = attr_dict.get("method", None)
    trigger_req.endpoint = attr_dict.get("path", None)
    trigger_req.query_params = attr_dict.get("query", None)
    
    # 計算持續時間（使用原始 root_span 作為基準）
    start_time_ns = int(root_span.get("startTimeUnixNano", 0))
    end_time_ns = int(root_span.get("endTimeUnixNano", 0))
    if start_time_ns and end_time_ns:
        trigger_req.duration_ms = (end_time_ns - start_time_ns) / 1e6
    
    # 保留原始 attributes 以供 LLM 使用
    trigger_req.attributes = attr_dict
    
    span_source = "next_span" if next_span else "root_span"
    logger.info(f"[Trigger] Source: {span_source}, Method: {trigger_req.method}, Endpoint: {trigger_req.endpoint}")
    
    return trigger_req

def filter_log_fields(log_str: str) -> str:
    """
    從 log 字串中僅保留重要欄位: ts, level, caller, msg, trace_id, span_id
    """
    try:
        log_json = json.loads(log_str)
        if isinstance(log_json, dict):
            important_fields = ["ts", "level", "caller", "msg", "trace_id", "span_id"]
            filtered = {k: v for k, v in log_json.items() if k in important_fields}
            return json.dumps(filtered, ensure_ascii=False)
    except (json.JSONDecodeError, ValueError):
        pass
    # 若無法解析為 JSON，返回原字串
    return log_str

def build_timeline_from_trace_and_logs(trace_data: Dict, context_logs: List[Dict], root_span_start_ns: int) -> List[str]:
    """
    組成僅含 log 字串的 timeline，來源包含 trace 內的 log 事件與 context logs
    """
    collected: List[tuple[int, str]] = []

    # Trace events (log-like) from spans
    if trace_data and "batches" in trace_data:
        for batch in trace_data.get("batches", []):
            for span_set in batch.get("scopeSpans", []):
                for span in span_set.get("spans", []):
                    for event in span.get("events", []):
                        ts_ns = int(event.get("timeUnixNano", 0))
                        message = None
                        for attr in event.get("attributes", []):
                            if "key" in attr and "value" in attr and attr["key"] in ["log.message", "message", "msg", "log"]:
                                val = attr["value"]
                                if "stringValue" in val:
                                    message = val["stringValue"]
                                break
                        if message:
                            filtered_message = filter_log_fields(message)
                            collected.append((ts_ns, filtered_message))

    # Context logs
    for log_entry in context_logs:
        if isinstance(log_entry, dict) and "timestamp" in log_entry:
            ts_ns = int(log_entry["timestamp"].timestamp() * 1e9)
            raw_log = log_entry.get("log", log_entry.get("message", ""))
            message = raw_log if isinstance(raw_log, str) else extract_log_message(raw_log)
            filtered_message = filter_log_fields(message)
            collected.append((ts_ns, filtered_message))

    collected.sort(key=lambda x: x[0])
    logger.info(f"[Timeline] Built timeline with {len(collected)} log events")
    return [msg for _, msg in collected]

def extract_log_message(log_content: Any) -> str:
    """從各種日誌格式中抽取 message 字串"""
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
    """將 labels、時間區間與 regex_filter 組成 LogQL 與 query_range 參數"""
    # 組建 LogQL: {app="backend", level=~"warn|error|fatal"}
    # 支援 level 為陣列的多值標籤
    labels = dict(labels)  # 避免修改原始輸入

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

    logger.info(f"Time range: {start} to {end}")
    logger.info(f"LogQL: {params['query']}")

    return params

# --- 核心邏輯 ---

async def scan_for_errors(client: httpx.AsyncClient, labels: Dict[str, Any], start: datetime, end: datetime, regex_filter: str) -> List[tuple]:
    """
    第一階段：掃描所有符合 level 的日誌
    回傳值: List[(timestamp, log_line, trace_id)]
    """
    labels["level"] = ["warn", "error", "fatal"]
    params = build_logql_and_params(start, end, 1000, labels, regex_filter, "backward")
    
    try:
        resp = await client.get(
            f"{LOKI_URL}/loki/api/v1/query_range", 
            params=params,
            headers=get_auth_headers()
        )
        resp.raise_for_status()
        data = resp.json()
        
        logger.info(f"[Phase 1] Loki response status: {resp.status_code}")
        logger.debug(f"[Phase 1] Loki response: {len(data.get('data', {}).get('result', []))} streams")
        
        found_events = []
        total_logs = 0
        if "data" in data and "result" in data["data"]:
            for stream in data["data"]["result"]:
                logger.info(f"[Phase 1] Stream labels: {stream.get('stream', {})}")
                for values in stream["values"]:
                    total_logs += 1
                    # values: ["1698400000000000000", "log content..."]
                    ts = extract_timestamp_from_loki_result(values)
                    log_content = values[1]
                    tid = extract_trace_id(log_content)
                    
                    logger.debug(f"[Phase 1] Log #{total_logs}: {log_content[:100]}... | TraceID: {tid}")
                    
                    if tid:
                        found_events.append((ts, log_content, tid))
        
        logger.info(f"[Phase 1] Found {len(found_events)} error logs with Trace IDs (out of {total_logs} total logs).")
        
        # Fallback: If no errors found, scan all logs to verify data availability
        if total_logs == 0:
            logger.warning(f"[Phase 1] No error logs found.")
            return []
        
        return found_events
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return []

async def fetch_incident_context(client: httpx.AsyncClient, incident: Incident, labels: Dict[str, str], window_sec: int):
    """
    第二階段 A：針對單一事件，撈取前後 window_sec 秒內所有 error/warn/fatal log
    """
    center_ts = incident.timestamp
    start_ts = center_ts - timedelta(seconds=window_sec)
    end_ts = center_ts + timedelta(seconds=window_sec)
    # 僅撈取 error/warn/fatal
    ctx_labels = dict(labels)
    ctx_labels["level"] = ["error", "warn", "fatal"]
    params = build_logql_and_params(start_ts, end_ts, 500, ctx_labels, None, "forward")
    
    try:
        resp = await client.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params,
            headers=get_auth_headers()
        )
        if resp.status_code == 200:
            data = resp.json()
            logs = []
            
            if "data" in data and "result" in data["data"]:
                for stream in data["data"]["result"]:
                    for values in stream["values"]:
                        ts = extract_timestamp_from_loki_result(values)
                        log_content = values[1]
                        trace_id = extract_trace_id(log_content)
                        
                        logs.append({
                            "timestamp": ts,
                            "log": log_content,
                            "trace_id": trace_id,
                            "level": "error"  # 簡化假設
                        })
            
            incident.context_logs = logs
    except Exception as e:
        logger.error(f"Context fetch failed for {incident.trace_id}: {e}")

async def fetch_tempo_trace(client: httpx.AsyncClient, incident: Incident):
    """
    第二階段 B：從 Tempo 獲取 Trace 結構
    修改建議 A: 解析 Root Span 獲取 Request Info
    """
    try:
        resp = await client.get(
            f"{TEMPO_URL}/api/traces/{incident.trace_id}",
            headers=get_auth_headers()
        )
        if resp.status_code == 200:
            incident.trace_detail = resp.json()
            
            # 解析 Root Span 並提取 Trigger Request
            root_span = find_root_span(incident.trace_detail)
            if root_span:
                # 找到 root span 的下一個子 span（包含重要的 HTTP attribute）
                next_span = find_next_span(incident.trace_detail, root_span)
                incident.trigger_request = extract_trigger_request(root_span, next_span)
                
                # 獲取 root span 的開始時間，用於計算時間偏移
                root_span_start_ns = int(root_span.get("startTimeUnixNano", 0))
                
                # 建構 Timeline（修改建議 B）
                incident.timeline = build_timeline_from_trace_and_logs(
                    incident.trace_detail,
                    incident.context_logs,
                    root_span_start_ns
                )
        elif resp.status_code == 404:
            logger.warning(f"Trace {incident.trace_id} not found in Tempo.")
    except Exception as e:
        logger.error(f"Tempo fetch failed for {incident.trace_id}: {e}")

async def fetch_context_requests(client: httpx.AsyncClient, incident: Incident, labels: Dict[str, str], window_sec: int):
    """
    第二階段 C：獲取 window 內所有 trace 的 HTTP 請求信息
    """
    center_ts = incident.timestamp
    start_ts = center_ts - timedelta(seconds=window_sec)
    end_ts = center_ts + timedelta(seconds=window_sec)
    
    # 從 Loki 獲取該時間窗口內的所有 trace_id（不限 level）
    ctx_labels = dict(labels)
    if "level" in ctx_labels:
        del ctx_labels["level"]
    
    params = build_logql_and_params(start_ts, end_ts, 1000, ctx_labels, None, "forward")
    
    trace_info = {}  # {trace_id: timestamp}
    try:
        resp = await client.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params=params,
            headers=get_auth_headers()
        )
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "result" in data["data"]:
                for stream in data["data"]["result"]:
                    for values in stream["values"]:
                        ts = extract_timestamp_from_loki_result(values)
                        log_content = values[1]
                        tid = extract_trace_id(log_content)
                        if tid and tid != incident.trace_id:
                            # 保留最早的時間戳
                            if tid not in trace_info:
                                trace_info[tid] = ts
        
        logger.info(f"[Context Requests] Found {len(trace_info)} traces in window for {incident.trace_id}")
        
        # 對每個 trace_id 查詢 Tempo 並提取請求信息
        context_requests = []
        for tid, ts in list(trace_info.items())[:50]:  # 限制最多 50 個請求避免過載
            try:
                trace_resp = await client.get(
                    f"{TEMPO_URL}/api/traces/{tid}",
                    headers=get_auth_headers()
                )
                if trace_resp.status_code == 200:
                    trace_data = trace_resp.json()
                    root_span = find_root_span(trace_data)
                    if root_span:
                        next_span = find_next_span(trace_data, root_span)
                        span_to_extract = next_span if next_span else root_span
                        
                        if span_to_extract:
                            attributes = span_to_extract.get("attributes", [])
                            method = None
                            endpoint = None
                            query = None
                            
                            for attr in attributes:
                                if "key" in attr and "value" in attr:
                                    key = attr["key"]
                                    value = attr["value"]
                                    if "stringValue" in value:
                                        if key == "method":
                                            method = value["stringValue"]
                                        elif key == "path":
                                            endpoint = value["stringValue"]
                                        elif key == "query":
                                            query = value["stringValue"]
                            
                            if method and endpoint:
                                timestamp_str = ts.isoformat()
                                request_str = f"{timestamp_str} {method} {endpoint}"
                                if query:
                                    request_str += f"?{query}"
                                context_requests.append(request_str)
            except Exception as e:
                logger.debug(f"Failed to fetch context trace {tid}: {e}")
                continue
        
        incident.context_requests = context_requests
        logger.info(f"[Context Requests] Collected {len(context_requests)} requests for {incident.trace_id}")
        
    except Exception as e:
        logger.error(f"Context requests fetch failed for {incident.trace_id}: {e}")

async def process_incident(client: httpx.AsyncClient, incident: Incident, labels: Dict, window: int):
    """組合 Context 與 Trace 查詢"""
    await asyncio.gather(
        fetch_incident_context(client, incident, labels, window),
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
    context_window_sec = scan_settings.get("context_window_seconds", 5)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Phase 1: Scan error logs
        raw_events = await scan_for_errors(
            client, 
            labels, 
            start_time, 
            end_time, 
            None
        )
        
        # 去重複 (Deduplicate by Trace ID)
        # 避免同一個 Request 連續噴錯導致重複查詢
        unique_incidents: Dict[str, Incident] = {}
        for ts, content, tid in raw_events:
            # 這裡簡單採用「最後一筆」作為基準點
            unique_incidents[tid] = Incident(trace_id=tid, timestamp=ts, error_log=content)
            
        logger.info(f"[Phase 1] Identified {len(unique_incidents)} unique incidents (Trace IDs).")
        
        # Phase 2: 平行擴充資料 (Enrich)
        tasks = []
        # 使用 Semaphore 控制併發數量，避免灌爆 Tempo/Loki
        semaphore = asyncio.Semaphore(max_concurrent_tasks)
        
        # 篩選出需要取 context 的 incident，避免重複覆蓋
        filtered_incidents = []
        for inc in unique_incidents.values():
            should_fetch_context = True
            # 檢查這個 incident 的時間是否已經被其他 incident 的 context_window 覆蓋
            for existing_inc in filtered_incidents:
                inc_window_start = existing_inc.timestamp - timedelta(seconds=context_window_sec)
                inc_window_end = existing_inc.timestamp + timedelta(seconds=context_window_sec)
                if inc_window_start <= inc.timestamp <= inc_window_end:
                    logger.info(f"[Phase 2] Incident {inc.trace_id} skipped (already covered by {existing_inc.trace_id}'s context window)")
                    should_fetch_context = False
                    break
            
            if should_fetch_context:
                filtered_incidents.append(inc)

        async def sem_task(inc):
            async with semaphore:
                return await process_incident(
                    client, 
                    inc, 
                    labels, 
                    context_window_sec
                )

        for incident in filtered_incidents:
            tasks.append(sem_task(incident))
        
        if tasks:
            enriched_incidents = await asyncio.gather(*tasks)
        else:
            enriched_incidents = []
        
        logger.info(f"[Phase 2] Fetched context for {len(enriched_incidents)} incidents (skipped {len(unique_incidents) - len(enriched_incidents)} duplicates)")

    # 建立輸出資料夾
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = f"incident_report_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    
    # 產生 meta.json
    meta_data = {
        "task": config.get("task_name"),
        "scan_range": f"{start_time} - {end_time}",
        "total_incidents": len(enriched_incidents),
        "generated_at": timestamp
    }
    
    with open(os.path.join(output_dir, "meta.json"), 'w', encoding='utf-8') as f:
        json.dump(meta_data, f, indent=2, ensure_ascii=False)
    
    # 每個 incident 輸出為單獨的 JSON 檔案
    for idx, inc in enumerate(enriched_incidents, 1):
        # 構建 LLM 友善的資料結構
        trigger_req_data = None
        if inc.trigger_request:
            trigger_req_data = {
                "method": inc.trigger_request.method,
                "endpoint": inc.trigger_request.endpoint,
                "query_params": inc.trigger_request.query_params,
                "duration_ms": inc.trigger_request.duration_ms,
                "attributes": inc.trigger_request.attributes
            }
        
        # 將 TimelineEvent 轉為可序列化的字典
        timeline_data = inc.timeline  # list[str] of log lines

        # 將 context_logs 中的 datetime 轉為字串
        serializable_context_logs = []
        for log in inc.context_logs:
            serializable_log = dict(log)
            if "timestamp" in serializable_log and isinstance(serializable_log["timestamp"], datetime):
                serializable_log["timestamp"] = str(serializable_log["timestamp"])
            serializable_context_logs.append(serializable_log)
        
        incident_data = {
            "incident_summary": {
                "trace_id": inc.trace_id,
                "timestamp": str(inc.timestamp),
                "service_name": config.get("labels", {}).get("service_name", "unknown")
            },
            "trigger_request": trigger_req_data,
            "context_requests": inc.context_requests,
            "timeline": timeline_data,
            "trace_dump": inc.trace_detail  # 保留原始 trace 以供參考
        }
        
        # 使用 trace_id 前 8 碼 + 序號作為檔名
        trace_id_short = inc.trace_id[:8]
        
        # --- 輸出完整版本 (Full) ---
        filename_full = f"incident_{idx:04d}_{trace_id_short}-full.json"
        filepath_full = os.path.join(output_dir, filename_full)
        
        with open(filepath_full, 'w', encoding='utf-8') as f:
            json.dump(incident_data, f, indent=2, ensure_ascii=False)
    
    logger.info(f"Report generated in directory: {output_dir}/")
    logger.info(f"Total files: meta.json + {len(enriched_incidents)} incident files (x2: -full.json and -summary.json)")

if __name__ == "__main__":
    asyncio.run(main())