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

func (s *Service) BuildPrompt(ctx context.Context, promptPath string, payload string) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "BuildPrompt")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	b, err := os.ReadFile(promptPath)
	if err != nil {
		logger.Error("failed to read prompt template", zap.String("path", promptPath), zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	tpl := string(b)

	// MVP：template + "\n\n" + payload
	// if needed, can change to strings.Replace(tpl, "{{INPUT}}", payload, 1)
	combined := tpl
	if strings.TrimSpace(combined) != "" && strings.TrimSpace(payload) != "" {
		combined += "\n\n"
	}
	combined += payload

	return combined, nil
}

// BuildPromptWithParams reads a prompt template and replaces placeholders with provided parameters
func (s *Service) BuildPromptWithParams(ctx context.Context, promptPath string, params map[string]string) (string, error) {
	traceCtx, span := s.tracer.Start(ctx, "BuildPromptWithParams")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	b, err := os.ReadFile(promptPath)
	if err != nil {
		logger.Error("failed to read prompt template", zap.String("path", promptPath), zap.Error(err))
		span.RecordError(err)
		return "", err
	}

	prompt := string(b)

	// Replace all placeholders with provided parameters
	for key, value := range params {
		placeholder := "{{" + key + "}}"
		prompt = strings.ReplaceAll(prompt, placeholder, value)
	}

	return prompt, nil
}

func (s *Service) ChatText(ctx context.Context, text string) (Response, error) {
	req := GeminiAPIRequest{
		Contents: []Content{
			{Parts: []Part{{Text: text}}},
		},
	}
	resp, err := s.Chat(ctx, req)
	if err != nil {
		return Response{}, err
	}
	return resp, nil
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

// ExtractUniqueCallers extract callers from the Grafana log
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
		return nil, fmt.Errorf("unmarshal incident json: %w", err)
	}

	callersSet := make(map[string]struct{})

	for _, line := range incident.Timeline {
		prefix := ""
		rest := strings.TrimSpace(strings.TrimPrefix(line.(string), prefix))
		i := strings.Index(rest, "{")
		if i < 0 {
			continue
		}
		jsonPart := strings.TrimSpace(rest[i:])

		var e LogMessage
		if err := json.Unmarshal([]byte(jsonPart), &e); err != nil {
			continue
		}
		if e.Caller == "" {
			continue
		}

		if i := strings.LastIndex(e.Caller, ":"); i > 0 {
			callersSet[e.Caller[:i]] = struct{}{}
		}
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

// classifyFailure classifies the failure type based on the output string
func classifyFailure(out string) FailureType {
	s := out

	// ---- compile/build (go run compilation) ----
	if strings.Contains(s, "# command-line-arguments") ||
		strings.Contains(s, "imported and not used") ||
		strings.Contains(s, "undefined: ") ||
		strings.Contains(s, "cannot use") ||
		strings.Contains(s, "too many arguments") ||
		strings.Contains(s, "not enough arguments") ||
		strings.Contains(s, "syntax error") {
		return FailureCompile
	}

	// ---- module/env issues ----
	if strings.Contains(s, "go: downloading") && strings.Contains(s, "error") {
		return FailureEnv
	}
	if strings.Contains(s, "go: ") && (strings.Contains(s, "missing go.sum entry") ||
		strings.Contains(s, "no required module provides package") ||
		strings.Contains(s, "cannot find module providing package") ||
		strings.Contains(s, "module ") && strings.Contains(s, "not found") ||
		strings.Contains(s, "GOPROXY") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "TLS handshake timeout")) {
		return FailureEnv
	}

	// ---- panic/runtime ----
	if strings.Contains(s, "panic:") ||
		strings.Contains(s, "fatal error:") {
		return FailureRuntime
	}

	return FailureRuntime
}

// ValidateScript check exit code/timeout first, then check output for expected error patterns or marker
// expectedErrors: slice of error messages/patterns to look for in output (empty means use default marker)
func (s *Service) ValidateScript(ctx context.Context, path string, expectedErrors []string) (RunScriptResult, EvaluateResult, error) {
	run, err := s.RunScript(ctx, path, RunScriptOptions{})
	if err != nil {
		return RunScriptResult{}, EvaluateResult{}, err
	}

	out := run.Stdout + "\n" + run.Stderr

	// 0) timeout
	if run.TimedOut {
		return run, EvaluateResult{
			Reproduced: false,
			NeedRetry:  true,
			Reason:     "script timed out",
			Failure:    FailureTimeout,
			Next:       ActionTune,
		}, nil
	}

	// 1) non-zero exit code：compile/env/runtime
	if run.ExitCode != 0 {
		switch classifyFailure(out) {
		case FailureCompile:
			return run, EvaluateResult{
				Reproduced: false,
				NeedRetry:  true,
				Reason:     "compile/build failed",
				Failure:    FailureCompile,
				Next:       ActionFixScript,
			}, nil
		case FailureEnv:
			// e.g. go mod / module / sum / download
			return run, EvaluateResult{
				Reproduced: false,
				NeedRetry:  true,
				Reason:     "environment/module resolution failed",
				Failure:    FailureEnv,
				Next:       ActionFixScript,
			}, nil
		default:
			// non 0 exit: mostly runtime panic or http client crash
			return run, EvaluateResult{
				Reproduced: false,
				NeedRetry:  true,
				Reason:     "runtime error (non-zero exit)",
				Failure:    FailureRuntime,
				Next:       ActionRethink,
			}, nil
		}
	}

	// 2) exit 0：inspect error message or the marker
	reproduced := false
	matchedErrors := []string{}

	if len(expectedErrors) > 0 {
		for _, expectedErr := range expectedErrors {
			if strings.Contains(out, expectedErr) {
				reproduced = true
				matchedErrors = append(matchedErrors, expectedErr)
			}
		}
		if reproduced {
			reason := fmt.Sprintf("found expected error patterns: %s", strings.Join(matchedErrors, ", "))
			return run, EvaluateResult{
				Reproduced:     true,
				NeedRetry:      false,
				Reason:         reason,
				Failure:        FailureNone,
				Next:           ActionStop,
				ExpectedErrors: expectedErrors,
			}, nil
		}
	} else {
		if strings.Contains(out, "Error Reproduced Successfully") {
			return run, EvaluateResult{
				Reproduced:     true,
				NeedRetry:      false,
				Reason:         "marker found",
				Failure:        FailureNone,
				Next:           ActionStop,
				ExpectedErrors: []string{"Error Reproduced Successfully"},
			}, nil
		}
	}

	// 3) exit 0
	return run, EvaluateResult{
		Reproduced: false,
		NeedRetry:  true,
		Reason:     "expected marker not found in output",
		Failure:    FailureNoRepro,
		Next:       ActionRerun,
	}, nil
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

func (s *Service) Retry(ctx context.Context, path string, marker []string) ([]RegenerateResponse, error) {
	traceCtx, span := s.tracer.Start(ctx, "Retry")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	const maxAttempts = 3
	resp := make([]RegenerateResponse, 0, maxAttempts)

	// First validation attempt
	run, ev, err := s.ValidateScript(traceCtx, path, marker)
	if err != nil {
		logger.Warn("Attempt 1: Validation failed", zap.Error(err))
	}
	resp = append(resp, RegenerateResponse{Attempt: 1, Run: run, Eval: ev})

	// Retry loop
	for attemptNum := 2; attemptNum <= maxAttempts && ev.NeedRetry; attemptNum++ {
		logger.Info("Starting retry attempt",
			zap.Int("attempt", attemptNum),
			zap.Int("max_attempts", maxAttempts),
			zap.String("next_action", string(ev.Next)),
		)

		var retryScriptText Response

		switch ev.Next {
		case ActionFixScript:
			// Handle compilation/build errors
			logger.Info("Using FIX_SCRIPT strategy", zap.Int("attempt", attemptNum))
			currentScript, _ := os.ReadFile(path)
			fixParams := FixScriptParams{
				Stderr:        run.Stderr,
				CurrentScript: string(currentScript),
			}
			fixPrompt, err := s.BuildPromptWithParams(traceCtx, "internal/gemini/prompts/fix_script.txt", fixParams.ToMap())
			if err != nil {
				logger.Error("Failed to build fix_script prompt", zap.Error(err), zap.Int("attempt", attemptNum))
				return resp, err
			}
			retryScriptText, err = s.ChatText(traceCtx, fixPrompt)
			if err != nil {
				logger.Error("Failed to generate fixed script", zap.Error(err), zap.Int("attempt", attemptNum))
				return resp, err
			}

		case ActionRethink:
			// Handle reproduction strategy issues
			logger.Info("Using RETHINK strategy", zap.Int("attempt", attemptNum))
			currentScript, _ := os.ReadFile(path)

			// Build summary of previous attempts
			prevAttempts := fmt.Sprintf("Previous attempts: %d", attemptNum-1)
			for _, r := range resp {
				prevAttempts += fmt.Sprintf("\n- Attempt %d: ExitCode=%d, Reproduced=%v, Reason=%s",
					r.Attempt, r.Run.ExitCode, r.Eval.Reproduced, r.Eval.Reason)
			}

			rethinkParams := RethinkScriptParams{
				ExpectedKeywords:     "tenant not found, nil UUID, 00000000-0000-0000-0000-000000000000",
				ExpectedEndpoints:    "/api/orgs/:slug",
				ExpectedErrorPattern: "unable to find tenants with id '00000000-0000-0000-0000-000000000000'",
				RunSummary:           prevAttempts,
				ObservationNotes:     ev.Reason,
				CurrentScript:        string(currentScript),
			}
			rethinkPrompt, err := s.BuildPromptWithParams(traceCtx, "internal/gemini/prompts/rethink_script.txt", rethinkParams.ToMap())
			if err != nil {
				logger.Error("Failed to build rethink_script prompt", zap.Error(err), zap.Int("attempt", attemptNum))
				return resp, err
			}
			retryScriptText, err = s.ChatText(traceCtx, rethinkPrompt)
			if err != nil {
				logger.Error("Failed to generate rethought script", zap.Error(err), zap.Int("attempt", attemptNum))
				return resp, err
			}

		default:
			// Simple rerun or unknown action
			logger.Info("Rerunning without modification", zap.Int("attempt", attemptNum))
			run, ev, err := s.ValidateScript(traceCtx, path, marker)
			if err != nil {
				logger.Warn("Validation attempt failed", zap.Error(err), zap.Int("attempt", attemptNum))
			}
			resp = append(resp, RegenerateResponse{Attempt: attemptNum, Run: run, Eval: ev})
			continue
		}

		// Write the regenerated script
		if retryScriptText.Text != "" {
			newFilePath, err := WriteCodeToFile(retryScriptText, "scripts/auto_race_reproduction")
			if err != nil {
				logger.Error("Failed to write regenerated script", zap.Error(err), zap.Int("attempt", attemptNum))
				return resp, err
			}
			logger.Info("Regenerated script written",
				zap.String("path", newFilePath),
				zap.Int("attempt", attemptNum),
			)

			// Update path to the new script
			path = newFilePath

			// Validate the regenerated script
			run, ev, err := s.ValidateScript(traceCtx, path, marker)
			if err != nil {
				logger.Warn("Validation attempt failed", zap.Error(err), zap.Int("attempt", attemptNum))
			}
			resp = append(resp, RegenerateResponse{Attempt: attemptNum, Run: run, Eval: ev})

			// Log success if reproduced
			if ev.Reproduced {
				logger.Info("Successfully reproduced error!", zap.Int("attempt", attemptNum))
				break
			}
		}
	}

	return resp, nil
}
