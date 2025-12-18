package gemini

import (
	"NYCU-SDC/core-system-backend/internal"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"github.com/NYCU-SDC/summer/pkg/problem"
	"github.com/go-playground/validator/v10"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	maxUploadSizeBytes = 1 << 20 // 1MB cap for uploaded text files
)

type ErrorReproducerRequest struct {
	Path string `json:"path"`
}

type RegenerateResponse struct {
	Eval    EvaluateResult  `json:"eval"`
	Attempt int             `json:"attempt"`
	Run     RunScriptResult `json:"run"`
}

type ChatOperator interface {
	BuildPrompt(ctx context.Context, promptPath string, payload string) (string, error)
	BuildPromptWithParams(ctx context.Context, promptPath string, params map[string]string) (string, error)
	ChatText(ctx context.Context, text string) (Response, error)
	Chat(ctx context.Context, req GeminiAPIRequest) (Response, error)
	ExtractUniqueCallers(ctx context.Context) ([]string, error)
	ExtractUniqueCallersFromContent(ctx context.Context, content string) ([]string, error)
	GetFileContent(ctx context.Context, filenames []string) (map[string]string, error)
	RunScript(ctx context.Context, path string, opt RunScriptOptions) (RunScriptResult, error)
	ValidateScript(ctx context.Context, path string, expectedErrors []string) (RunScriptResult, EvaluateResult, error)
	Retry(ctx context.Context, path string, marker []string) ([]RegenerateResponse, error)
}

type Handler struct {
	logger        *zap.Logger
	validator     *validator.Validate
	problemWriter *problem.HttpWriter
	operator      ChatOperator
	tracer        trace.Tracer
}

func NewHandler(logger *zap.Logger, validator *validator.Validate, problemWriter *problem.HttpWriter, operator ChatOperator) *Handler {
	return &Handler{
		logger:        logger,
		validator:     validator,
		problemWriter: problemWriter,
		operator:      operator,
		tracer:        otel.Tracer("gemini/handler"),
	}
}

// LogAnalysisResult contains the results of two-stage log analysis
type LogAnalysisResult struct {
	Triage struct {
		AnalysisMode     AnalysisMode `json:"analysis_mode"`
		DetectedKeywords []string     `json:"detected_keywords"`
		PrimaryErrorLog  string       `json:"primary_error_log"`
	} `json:"triage"`
	ExpertAnalysis    interface{} `json:"expert_analysis"`
	ExpertAnalysisRaw string      `json:"expert_analysis_raw"`
}

// performLogAnalysis executes two-stage log analysis with triage and expert phases
// This method is shared between AnalyzeLogHandler and ErrorReproducerHandler
func (h *Handler) performLogAnalysis(ctx context.Context, logger *zap.Logger, logContent string, triagePromptText string, expertPrompts map[string]string) (*LogAnalysisResult, error) {
	// Extract callers from log content and fetch source code files for enhanced context
	logger.Info("Extracting callers from log content")
	callers, err := h.operator.ExtractUniqueCallersFromContent(ctx, logContent)
	if err != nil {
		// Non-blocking: log warning but continue without source code context
		logger.Warn("Failed to extract callers from log content, continuing without source code context", zap.Error(err))
		callers = []string{}
	}

	var sourceCodeContext string
	if len(callers) > 0 {
		logger.Info("Fetching source code files from GitHub", zap.Int("file_count", len(callers)), zap.Strings("files", callers))
		fileContents, err := h.operator.GetFileContent(ctx, callers)
		if err != nil {
			// Non-blocking: log warning but continue without source code context
			logger.Warn("Failed to fetch source code files, continuing without source code context", zap.Error(err))
		} else if len(fileContents) > 0 {
			// Format source code context
			var contextBuilder strings.Builder
			contextBuilder.WriteString("\n\n## Relevant Source Code Files\n\n")
			contextBuilder.WriteString("The following source code files were referenced in the logs and may be relevant for analysis:\n\n")
			for filename, content := range fileContents {
				contextBuilder.WriteString(fmt.Sprintf("### File: %s\n\n```\n%s\n```\n\n", filename, content))
			}
			sourceCodeContext = contextBuilder.String()
			logger.Info("Successfully fetched source code context", zap.Int("files_fetched", len(fileContents)))
		}
	}

	// Stage 1: Triage Classification
	logger.Info("Stage 1: Starting triage classification")
	triagePrompt := triagePromptText + "\n\n" + logContent + "\n\n" + sourceCodeContext
	triageReq := GeminiAPIRequest{
		Contents: []Content{
			{
				Parts: []Part{
					{Text: triagePrompt},
				},
			},
		},
	}

	triageResponse, err := h.operator.Chat(ctx, triageReq)
	if err != nil {
		logger.Error("Stage 1 failed", zap.Error(err))
		return nil, fmt.Errorf("triage stage failed: %w", err)
	}

	// Parse triage response
	triageResult, err := ParseTriageResponse(triageResponse.Text)
	if err != nil {
		logger.Error("Failed to parse triage response", zap.Error(err), zap.String("response", triageResponse.Text))
		return nil, fmt.Errorf("failed to parse triage response: %w", err)
	}

	logger.Info("Stage 1 completed",
		zap.String("analysis_mode", string(triageResult.AnalysisMode)),
		zap.Strings("detected_keywords", triageResult.DetectedKeywords),
	)

	// Stage 2: Expert Analysis
	logger.Info("Stage 2: Starting expert analysis", zap.String("mode", string(triageResult.AnalysisMode)))
	expertPrompt, err := GetExpertPrompt(expertPrompts, triageResult.AnalysisMode)
	if err != nil {
		logger.Error("Failed to get expert prompt", zap.Error(err), zap.String("mode", string(triageResult.AnalysisMode)))
		return nil, fmt.Errorf("failed to get expert prompt: %w", err)
	}

	expertPromptWithContent := expertPrompt + "\n\n" + logContent + "\n\n" + sourceCodeContext
	expertReq := GeminiAPIRequest{
		Contents: []Content{
			{
				Parts: []Part{
					{Text: expertPromptWithContent},
				},
			},
		},
	}

	expertResponse, err := h.operator.Chat(ctx, expertReq)
	if err != nil {
		logger.Error("Stage 2 failed", zap.Error(err))
		return nil, fmt.Errorf("expert analysis stage failed: %w", err)
	}

	// Parse expert response into structured format
	structuredAnalysis, parseErr := ParseExpertResponse(expertResponse.Text)
	if parseErr != nil {
		// Non-blocking: if parsing fails, return original text
		logger.Warn("Failed to parse expert response into structured format, returning original text", zap.Error(parseErr))
		structuredAnalysis = nil
	}

	// Build result
	result := &LogAnalysisResult{
		ExpertAnalysisRaw: expertResponse.Text,
	}
	result.Triage.AnalysisMode = triageResult.AnalysisMode
	result.Triage.DetectedKeywords = triageResult.DetectedKeywords
	result.Triage.PrimaryErrorLog = triageResult.PrimaryErrorLog

	if structuredAnalysis != nil {
		result.ExpertAnalysis = structuredAnalysis
	} else {
		result.ExpertAnalysis = expertResponse.Text
	}

	return result, nil
}

// ChatHandler handles POST requests to the Gemini API endpoint
func (h *Handler) ChatHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ChatHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(maxUploadSizeBytes); err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}

		prompt := r.FormValue("prompt")
		var fileContent string

		file, _, err := r.FormFile("file")
		switch err {
		case nil:
			defer func() {
				if closeErr := file.Close(); closeErr != nil {
					logger.Warn("failed to close uploaded file", zap.Error(closeErr))
				}
			}()

			limited := io.LimitReader(file, maxUploadSizeBytes+1)
			data, readErr := io.ReadAll(limited)
			if readErr != nil {
				h.problemWriter.WriteError(traceCtx, w, readErr, logger)
				return
			}
			if int64(len(data)) > maxUploadSizeBytes {
				h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: uploaded file exceeds %d bytes", internal.ErrValidationFailed, maxUploadSizeBytes), logger)
				return
			}
			fileContent = string(data)
		case http.ErrMissingFile:
			// no file provided; prompt may still be present
		default:
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}

		if strings.TrimSpace(prompt) == "" && strings.TrimSpace(fileContent) == "" {
			h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: prompt or file is required", internal.ErrValidationFailed), logger)
			return
		}

		combined := prompt
		if prompt != "" && fileContent != "" {
			combined += "\n\n"
		}
		combined += fileContent

		geminiReq := GeminiAPIRequest{
			Contents: []Content{
				{
					Parts: []Part{
						{Text: combined},
					},
				},
			},
		}

		response, err := h.operator.Chat(traceCtx, geminiReq)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}

		handlerutil.WriteJSONResponse(w, http.StatusOK, response)
		return
	}

	var request Request
	err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	if len(request.Prompt) == 0 {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: prompt is required", internal.ErrValidationFailed), logger)
		return
	}

	// Convert request to Gemini API format
	geminiReq := request.ToGeminiAPIRequest()

	// Call the service
	response, err := h.operator.Chat(traceCtx, geminiReq)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, response)
}

// AnalyzeLogHandler handles POST requests for two-stage log analysis
// Stage 1: Triage classification
// Stage 2: Expert analysis based on classification
func (h *Handler) AnalyzeLogHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "AnalyzeLogHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	var request AnalyzeLogRequest

	// Handle multipart/form-data
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(maxUploadSizeBytes); err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}

		// Get file content
		file, _, err := r.FormFile("file")
		switch err {
		case nil:
			defer func() {
				if closeErr := file.Close(); closeErr != nil {
					logger.Warn("failed to close uploaded file", zap.Error(closeErr))
				}
			}()

			limited := io.LimitReader(file, maxUploadSizeBytes+1)
			data, readErr := io.ReadAll(limited)
			if readErr != nil {
				h.problemWriter.WriteError(traceCtx, w, readErr, logger)
				return
			}
			if int64(len(data)) > maxUploadSizeBytes {
				h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: uploaded file exceeds %d bytes", internal.ErrValidationFailed, maxUploadSizeBytes), logger)
				return
			}
			request.FileContent = string(data)
		case http.ErrMissingFile:
			h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: file is required", internal.ErrValidationFailed), logger)
			return
		default:
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}

		// Get triage prompt
		request.TriagePrompt = r.FormValue("triage_prompt")
		if strings.TrimSpace(request.TriagePrompt) == "" {
			h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: triage_prompt is required", internal.ErrValidationFailed), logger)
			return
		}

		// Get expert prompts (JSON string that needs to be parsed)
		expertPromptsJSON := r.FormValue("expert_prompts")
		if strings.TrimSpace(expertPromptsJSON) == "" {
			h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: expert_prompts is required", internal.ErrValidationFailed), logger)
			return
		}

		// Trim whitespace and handle potential encoding issues
		expertPromptsJSON = strings.TrimSpace(expertPromptsJSON)

		// Log the received JSON for debugging (truncate if too long)
		if len(expertPromptsJSON) > 500 {
			logger.Debug("Received expert_prompts", zap.String("preview", expertPromptsJSON[:500]+"..."))
		} else {
			logger.Debug("Received expert_prompts", zap.String("value", expertPromptsJSON))
		}

		if err := json.Unmarshal([]byte(expertPromptsJSON), &request.ExpertPrompts); err != nil {
			logger.Error("Failed to parse expert_prompts JSON",
				zap.Error(err),
				zap.String("received_json", expertPromptsJSON),
				zap.Int("json_length", len(expertPromptsJSON)),
			)
			h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: invalid expert_prompts JSON format: %w. Received: %s", internal.ErrValidationFailed, err, expertPromptsJSON), logger)
			return
		}
	} else {
		// Handle JSON body
		err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &request)
		if err != nil {
			h.problemWriter.WriteError(traceCtx, w, err, logger)
			return
		}
	}

	// Validate required fields
	if strings.TrimSpace(request.TriagePrompt) == "" {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: triage_prompt is required", internal.ErrValidationFailed), logger)
		return
	}
	if len(request.ExpertPrompts) == 0 {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: expert_prompts is required", internal.ErrValidationFailed), logger)
		return
	}
	if strings.TrimSpace(request.FileContent) == "" {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("%w: file_content is required", internal.ErrValidationFailed), logger)
		return
	}

	// Perform two-stage log analysis using shared method
	analysisResult, err := h.performLogAnalysis(traceCtx, logger, request.FileContent, request.TriagePrompt, request.ExpertPrompts)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	// Convert to map for response
	result := map[string]interface{}{
		"triage": map[string]interface{}{
			"analysis_mode":     analysisResult.Triage.AnalysisMode,
			"detected_keywords": analysisResult.Triage.DetectedKeywords,
			"primary_error_log": analysisResult.Triage.PrimaryErrorLog,
		},
		"expert_analysis":     analysisResult.ExpertAnalysis,
		"expert_analysis_raw": analysisResult.ExpertAnalysisRaw,
	}

	// Write response JSON to analysis.json file
	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		logger.Warn("Failed to marshal result to JSON for file writing", zap.Error(err))
	} else {
		if err := os.WriteFile("analysis.json", resultJSON, 0644); err != nil {
			logger.Warn("Failed to write analysis.json file", zap.Error(err))
		} else {
			logger.Info("Response JSON written to analysis.json")
		}
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, result)
}

func (h *Handler) CallerHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "CallerHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	callers, err := h.operator.ExtractUniqueCallers(traceCtx)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	contents, err := h.operator.GetFileContent(traceCtx, callers)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, contents)
}

func (h *Handler) RegenerateHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "RegenerateHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	path := "scripts/error_race_reproduction.go"
	marker := "unable to find tenants with id '00000000-0000-0000-0000-000000000000'"

	resp, err := h.operator.Retry(traceCtx, path, []string{marker})
	if err != nil {
		logger.Warn("Failed to execute regenerate request", zap.Error(err))
		return
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, resp)
}

func (h *Handler) ErrorReproducerHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "ErrorReproducerHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	// 1) Read log file content
	var req ErrorReproducerRequest
	err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	path := req.Path
	logContent, err := os.ReadFile(path)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("failed to read log file: %w", err), logger)
		return
	}

	// 2) Load expert prompts from file
	expertPromptsData, err := os.ReadFile("internal/gemini/prompts/generate_error_report_expert.txt")
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("failed to read expert prompts: %w", err), logger)
		return
	}

	var expertPrompts map[string]string
	if err := json.Unmarshal(expertPromptsData, &expertPrompts); err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("failed to parse expert prompts: %w", err), logger)
		return
	}

	// 3) Load triage prompt
	triagePrompt, err := os.ReadFile("internal/gemini/prompts/generate_error_report_triage.txt")
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("failed to read traige prompts: %w", err), logger)
		return
	}

	// 4) Perform two-stage log analysis using shared method
	analysisResult, err := h.performLogAnalysis(traceCtx, logger, string(logContent), string(triagePrompt), expertPrompts)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("log analysis failed: %w", err), logger)
		return
	}

	logger.Info("Stage 2: Analysis completed",
		zap.String("analysis_mode", string(analysisResult.Triage.AnalysisMode)),
	)

	// 5) Generate reproduction script based on analysis
	logger.Info("Stage 3: Generating reproduction script")
	scriptPrompt, err := h.operator.BuildPrompt(traceCtx, "internal/gemini/prompts/generate_script.txt", analysisResult.ExpertAnalysisRaw)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	scriptText, err := h.operator.ChatText(traceCtx, scriptPrompt)
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}

	filePath, err := WriteCodeToFile(scriptText, "scripts/auto_race_reproduction")
	if err != nil {
		h.problemWriter.WriteError(traceCtx, w, err, logger)
		return
	}
	logger.Info("Go code written to file", zap.String("filePath", filePath))

	// 6) Run the script and validate. Retry if needed with appropriate strategy
	logger.Info("Stage 4: Validating reproduction script")
	var attempts []RegenerateResponse
	path = "scripts/auto_race_reproduction.go"

	// Extract expected error messages from analysis result
	expectedErrors := make([]string, 0)
	if analysisResult.Triage.PrimaryErrorLog != "" {
		expectedErrors = append(expectedErrors, analysisResult.Triage.PrimaryErrorLog)
	}
	// Also include detected keywords as potential error indicators
	expectedErrors = append(expectedErrors, analysisResult.Triage.DetectedKeywords...)
	logger.Info("Expected error patterns for validation",
		zap.Strings("expected_errors", expectedErrors),
	)

	attempts, err = h.operator.Retry(traceCtx, path, expectedErrors)
	if err != nil {
		logger.Warn("Stage 4: Validation attempt failed", zap.Error(err))
		return
	}

	// Return comprehensive response
	handlerutil.WriteJSONResponse(w, http.StatusOK, map[string]any{
		"triage": map[string]interface{}{
			"analysis_mode":     analysisResult.Triage.AnalysisMode,
			"detected_keywords": analysisResult.Triage.DetectedKeywords,
			"primary_error_log": analysisResult.Triage.PrimaryErrorLog,
		},
		"expert_analysis": analysisResult.ExpertAnalysisRaw,
		"script_path":     filePath,
		"attempts":        attempts,
	})
}
