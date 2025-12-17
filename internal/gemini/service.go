package gemini

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	geminiAPIBaseURL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
	repoAPI          = "https://api.github.com/repos/NYCU-SDC/core-system-backend/contents/internal"
	summerAPI        = "https://api.github.com/repos/NYCU-SDC/summer/contents/pkg"
)

type EvaluateResult struct {
	Reproduced bool
	NeedRetry  bool
	Reason     string
}
type RunScriptOptions struct {
	WorkDir         string        // 可空；建議設成 repo root
	Timeout         time.Duration // 可空；例如 60s
	Env             []string      // 額外 env，會 append 到 os.Environ()
	MaxOutputBytes  int           // stdout/stderr 最大保留 bytes（避免爆）
	StdoutTailBytes int           // 另外提供 tail，方便丟回 LLM
	StderrTailBytes int
}
type RunScriptResult struct {
	Path     string
	ExitCode int
	TimedOut bool
	Duration time.Duration

	Stdout string
	Stderr string

	StdoutTail string
	StderrTail string

	// 如果你之後要做「最後一行 JSON summary」也可以先留欄位
	LastNonEmptyStdoutLine string
}

type Service struct {
	logger  *zap.Logger
	tracer  trace.Tracer
	apiKey  string
	logPath string
	client  *http.Client
}

func NewService(logger *zap.Logger, apiKey string, logPath string) *Service {
	return &Service{
		logger:  logger,
		tracer:  otel.Tracer("gemini/service"),
		apiKey:  apiKey,
		logPath: logPath,
		client:  &http.Client{},
	}
}

// Chat sends a request to the Gemini API and returns the response
func (s *Service) Chat(ctx context.Context, req GeminiAPIRequest) (Response, error) {
	traceCtx, span := s.tracer.Start(ctx, "Chat")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	if s.apiKey == "" {
		err := fmt.Errorf("gemini API key is not configured")
		logger.Error("gemini API key is missing", zap.Error(err))
		span.RecordError(err)
		return Response{}, err
	}

	// Marshal request to JSON
	reqBody, err := json.Marshal(req)
	if err != nil {
		logger.Error("failed to marshal request", zap.Error(err))
		span.RecordError(err)
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s?key=%s", geminiAPIBaseURL, s.apiKey)
	httpReq, err := http.NewRequestWithContext(traceCtx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		logger.Error("failed to create HTTP request", zap.Error(err))
		span.RecordError(err)
		return Response{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	logger.Info("sending request to Gemini API", zap.String("url", url))
	resp, err := s.client.Do(httpReq)
	if err != nil {
		logger.Error("failed to send request to Gemini API", zap.Error(err))
		span.RecordError(err)
		return Response{}, fmt.Errorf("failed to send request to Gemini API: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warn("failed to close response body", zap.Error(closeErr))
		}
	}()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("failed to read response body", zap.Error(err))
		span.RecordError(err)
		return Response{}, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("gemini API returned status %d: %s", resp.StatusCode, string(body))
		logger.Error("Gemini API returned error",
			zap.Int("status_code", resp.StatusCode),
			zap.String("response", string(body)),
		)
		span.RecordError(err)
		return Response{}, err
	}

	// Parse response
	var geminiResp GeminiAPIResponse
	if err := json.Unmarshal(body, &geminiResp); err != nil {
		logger.Error("failed to unmarshal response", zap.Error(err), zap.String("body", string(body)))
		span.RecordError(err)
		return Response{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for blocked content
	if geminiResp.PromptFeedback != nil && geminiResp.PromptFeedback.BlockReason != "" {
		err := fmt.Errorf("prompt was blocked: %s", geminiResp.PromptFeedback.BlockReason)
		logger.Error("prompt was blocked", zap.String("reason", geminiResp.PromptFeedback.BlockReason))
		span.RecordError(err)
		return Response{}, err
	}

	// Convert to simplified response
	response := geminiResp.ToResponse()
	logger.Info("successfully received response from Gemini API", zap.String("text_length", fmt.Sprintf("%d", len(response.Text))))

	return response, nil
}

func (s *Service) ExtractUniqueCallers(ctx context.Context) ([]string, error) {
	_, span := s.tracer.Start(ctx, "ExtractUniqueCallers")
	defer span.End()
	logger := logutil.WithContext(ctx, s.logger)

	content, err := os.ReadFile(s.logPath)
	if err != nil {
		logger.Error("failed to read log file", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	var incident Incident
	if err := json.Unmarshal(content, &incident); err != nil {
		logger.Error("failed to unmarshal log file", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	callersSet := make(map[string]struct{})

	for _, entry := range incident.Timeline {
		var msg LogMessage

		// Handle different timeline formats
		switch v := entry.(type) {
		case string:
			// New format: entry is a JSON string directly (e.g., incident_0001_59e41abb-full.json)
			err := json.Unmarshal([]byte(v), &msg)
			if err != nil {
				continue
			}
		case map[string]interface{}:
			// Old format: entry is an object with details.message
			details, ok := v["details"].(map[string]interface{})
			if !ok {
				continue
			}
			message, ok := details["message"].(string)
			if !ok || message == "" {
				continue
			}
			err := json.Unmarshal([]byte(message), &msg)
			if err != nil {
				continue
			}
		default:
			// Try to unmarshal as old format TimelineEntry
			entryBytes, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			var timelineEntry TimelineEntry
			if err := json.Unmarshal(entryBytes, &timelineEntry); err != nil {
				continue
			}
			if timelineEntry.Details == nil || timelineEntry.Details.Message == "" {
				continue
			}
			err = json.Unmarshal([]byte(timelineEntry.Details.Message), &msg)
			if err != nil {
				continue
			}
		}

		// Extract filename from caller
		if msg.Caller == "" {
			continue
		}

		parts := strings.Split(msg.Caller, ":")
		filename := parts[0]
		callersSet[filename] = struct{}{}
	}

	callers := make([]string, 0, len(callersSet))
	for c := range callersSet {
		callers = append(callers, c)
	}
	sort.Strings(callers)

	return callers, nil
}

// ExtractUniqueCallersFromContent extracts unique caller filenames from log content string
// This is similar to ExtractUniqueCallers but works with content instead of reading from file
func (s *Service) ExtractUniqueCallersFromContent(ctx context.Context, content string) ([]string, error) {
	_, span := s.tracer.Start(ctx, "ExtractUniqueCallersFromContent")
	defer span.End()
	logger := logutil.WithContext(ctx, s.logger)

	var incident Incident
	if err := json.Unmarshal([]byte(content), &incident); err != nil {
		logger.Error("failed to unmarshal log content", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	callersSet := make(map[string]struct{})

	for _, entry := range incident.Timeline {
		var msg LogMessage

		// Handle different timeline formats
		switch v := entry.(type) {
		case string:
			err := json.Unmarshal([]byte(v), &msg)
			if err != nil {
				continue
			}
		case map[string]interface{}:
			// Old format: entry is an object with details.message
			details, ok := v["details"].(map[string]interface{})
			if !ok {
				continue
			}
			message, ok := details["message"].(string)
			if !ok || message == "" {
				continue
			}
			err := json.Unmarshal([]byte(message), &msg)
			if err != nil {
				continue
			}
		default:
			// Try to unmarshal as old format TimelineEntry
			entryBytes, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			var timelineEntry TimelineEntry
			if err := json.Unmarshal(entryBytes, &timelineEntry); err != nil {
				continue
			}
			if timelineEntry.Details == nil || timelineEntry.Details.Message == "" {
				continue
			}
			err = json.Unmarshal([]byte(timelineEntry.Details.Message), &msg)
			if err != nil {
				continue
			}
		}

		// Extract filename from caller
		if msg.Caller == "" {
			continue
		}

		parts := strings.Split(msg.Caller, ":")
		filename := parts[0]
		callersSet[filename] = struct{}{}
	}

	callers := make([]string, 0, len(callersSet))
	for c := range callersSet {
		callers = append(callers, c)
	}
	sort.Strings(callers)

	return callers, nil
}

func (s *Service) fetchGithubFile(ctx context.Context, baseAPI, filename string) (string, int, error) {
	logger := logutil.WithContext(ctx, s.logger)

	fileURL := fmt.Sprintf("%s/%s",
		strings.TrimRight(baseAPI, "/"),
		strings.TrimLeft(filename, "/"),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		logger.Error("failed to create HTTP request", zap.Error(err))
		return "", 0, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.raw+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := s.client.Do(req)
	if err != nil {
		logger.Error("failed to send request to GitHub API", zap.Error(err))
		return "", 0, fmt.Errorf("failed to send request to GitHub API: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warn("failed to close response body", zap.Error(closeErr))
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("failed to read GitHub response body", zap.Error(err))
		return "", resp.StatusCode, fmt.Errorf("failed to read GitHub response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode,
			fmt.Errorf("github API status=%d body=%s", resp.StatusCode, string(body))
	}

	return string(body), http.StatusOK, nil
}

func (s *Service) GetFileContent(ctx context.Context, filenames []string) (map[string]string, error) {
	_, span := s.tracer.Start(ctx, "GetFileContent")
	defer span.End()
	logger := logutil.WithContext(ctx, s.logger)

	files := make(map[string]string, len(filenames))
	repoBases := []string{repoAPI, summerAPI}
	for _, filename := range filenames {
		var content string
		found := false

		for _, base := range repoBases {
			body, status, err := s.fetchGithubFile(ctx, base, filename)
			if err != nil {
				if status != http.StatusNotFound {
					span.RecordError(err)
					return nil, err
				}
				logger.Warn("file not found in repo", zap.String("repo", base), zap.String("filename", filename), zap.Error(err))
				continue
			}

			content = body
			found = true
			break
		}

		if !found {
			logger.Warn("file not found in any repo", zap.String("filename", filename))
			continue
		}

		files[filename] = content
	}
	return files, nil
}

func (s *Service) ValidateScriptRun(ctx context.Context, path string) (RunScriptResult, EvaluateResult, error) {
	run, err := s.RunScript(ctx, path, RunScriptOptions{})
	if err != nil {
		return RunScriptResult{}, EvaluateResult{}, err // 只有 IO/系統錯才回 error
	}

	// MVP：Compare with the keyword
	out := run.Stdout + "\n" + run.Stderr
	reproduced := strings.Contains(out, "Error Reproduced Successfully")

	// Fallback: Having specific signature
	if !reproduced {
		if strings.Contains(out, "Failed to get tenant by id") ||
			strings.Contains(out, "NotFoundError") ||
			strings.Contains(out, "00000000-0000-0000-0000-000000000000") {
			reproduced = true
		}
	}

	// if not reproduced then retry
	ev := EvaluateResult{
		Reproduced: reproduced,
		NeedRetry:  !reproduced,
	}
	if ev.NeedRetry {
		ev.Reason = "expected marker not found in output"
	}
	return run, ev, nil
}

func (s *Service) RunScript(ctx context.Context, path string, opt RunScriptOptions) (RunScriptResult, error) {
	traceCtx, span := s.tracer.Start(ctx, "RunScript")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	// ---- defaults ----
	if opt.Timeout <= 0 {
		opt.Timeout = 60 * time.Second
	}
	if opt.MaxOutputBytes <= 0 {
		opt.MaxOutputBytes = 128 * 1024 // 256KB
	}
	if opt.StdoutTailBytes <= 0 {
		opt.StdoutTailBytes = 2 * 1024 // 4KB
	}
	if opt.StderrTailBytes <= 0 {
		opt.StderrTailBytes = 2 * 1024
	}

	// ---- validate file exists ----
	_, err := os.Stat(path)
	if err != nil {
		logger.Warn("failed to find the script", zap.String("path", path))
		return RunScriptResult{Path: path}, err
	}

	// ---- context with timeout ----
	runCtx, cancel := context.WithTimeout(traceCtx, opt.Timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, "go", "run", path)
	if opt.WorkDir != "" {
		cmd.Dir = opt.WorkDir
	}
	if len(opt.Env) > 0 {
		cmd.Env = append(os.Environ(), opt.Env...)
	}

	// ---- capture stdout/stderr with size limit ----
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	err = cmd.Run()
	dur := time.Since(start)

	res := RunScriptResult{
		Path:     path,
		ExitCode: 0,
		TimedOut: errors.Is(runCtx.Err(), context.DeadlineExceeded),
		Duration: dur,
		Stdout:   stdoutBuf.String(),
		Stderr:   stderrBuf.String(),
	}

	// ---- exit code ----
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = -1
		}
	}

	// ---- useful tails + last line ----
	res.StdoutTail = tailString(res.Stdout, opt.StdoutTailBytes)
	res.StderrTail = tailString(res.Stderr, opt.StderrTailBytes)
	res.LastNonEmptyStdoutLine = lastNonEmptyLine(res.Stdout)

	// Leave for the upper layer to check.
	if res.TimedOut {
		logger.Warn("script timed out",
			zap.String("path", path),
			zap.Duration("timeout", opt.Timeout),
			zap.Duration("duration", dur),
		)
		return res, nil
	}

	logger.Info("script finished",
		zap.String("path", path),
		zap.Int("exit_code", res.ExitCode),
		zap.Duration("duration", dur),
	)

	return res, nil
}

func tailString(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func lastNonEmptyLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return strings.TrimSpace(lines[i])
		}
	}
	return ""
}
