package gemini

import (
	"NYCU-SDC/core-system-backend/internal"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

type RegenerateResponse struct {
	Eval    EvaluateResult  `json:"eval"`
	Attempt int             `json:"attempt"`
	Run     RunScriptResult `json:"run"`
}

type ChatOperator interface {
	Chat(ctx context.Context, req GeminiAPIRequest) (Response, error)
	RunScript(ctx context.Context, path string, opt RunScriptOptions) (RunScriptResult, error)
	ValidateScriptRun(ctx context.Context, path string) (RunScriptResult, EvaluateResult, error)
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

		// Write Go code to file if present in response
		filePath, err := WriteCodeToFile(response, "scripts/auto_race_reproduction")
		if err != nil {
			logger.Warn("Failed to extract and write Go code to file", zap.Error(err))
		} else {
			logger.Info("Go code written to file", zap.String("filePath", filePath))
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

	// Write Go code to file if present in response
	filePath, err := WriteCodeToFile(response, "scripts/auto_race_reproduction")
	if err != nil {
		logger.Warn("Failed to extract and write Go code to file", zap.Error(err))
	} else {
		logger.Info("Go code written to file", zap.String("filePath", filePath))
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

	logger.Info("Stage 1: Starting triage classification")
	triagePrompt := request.TriagePrompt + "\n\n" + request.FileContent
	triageReq := GeminiAPIRequest{
		Contents: []Content{
			{
				Parts: []Part{
					{Text: triagePrompt},
				},
			},
		},
	}

	triageResponse, err := h.operator.Chat(traceCtx, triageReq)
	if err != nil {
		logger.Error("Stage 1 failed", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("triage stage failed: %w", err), logger)
		return
	}

	// Parse triage response
	triageResult, err := ParseTriageResponse(triageResponse.Text)
	if err != nil {
		logger.Error("Failed to parse triage response", zap.Error(err), zap.String("response", triageResponse.Text))
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("failed to parse triage response: %w", err), logger)
		return
	}

	logger.Info("Stage 1 completed",
		zap.String("analysis_mode", string(triageResult.AnalysisMode)),
		zap.Strings("detected_keywords", triageResult.DetectedKeywords),
	)

	// Stage 2: Expert Analysis
	logger.Info("Stage 2: Starting expert analysis", zap.String("mode", string(triageResult.AnalysisMode)))
	expertPrompt, err := GetExpertPrompt(request.ExpertPrompts, triageResult.AnalysisMode)
	if err != nil {
		logger.Error("Failed to get expert prompt", zap.Error(err), zap.String("mode", string(triageResult.AnalysisMode)))
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("failed to get expert prompt: %w", err), logger)
		return
	}

	expertPromptWithContent := expertPrompt + "\n\n" + request.FileContent
	expertReq := GeminiAPIRequest{
		Contents: []Content{
			{
				Parts: []Part{
					{Text: expertPromptWithContent},
				},
			},
		},
	}

	expertResponse, err := h.operator.Chat(traceCtx, expertReq)
	if err != nil {
		logger.Error("Stage 2 failed", zap.Error(err))
		h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("expert analysis stage failed: %w", err), logger)
		return
	}

	// Return combined response
	result := map[string]interface{}{
		"triage": map[string]interface{}{
			"analysis_mode":     triageResult.AnalysisMode,
			"detected_keywords": triageResult.DetectedKeywords,
			"primary_error_log": triageResult.PrimaryErrorLog,
		},
		"expert_analysis": expertResponse.Text,
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, result)
}

func (h *Handler) RegenerateHandler(w http.ResponseWriter, r *http.Request) {
	traceCtx, span := h.tracer.Start(r.Context(), "RegenerateHandler")
	defer span.End()
	logger := logutil.WithContext(traceCtx, h.logger)

	var resp []RegenerateResponse
	path := "scripts/auto_race_reproduction.go"
	run, ev, err := h.operator.ValidateScriptRun(traceCtx, path)
	if err != nil {
		logger.Warn("failed to run script", zap.Error(err))
	}

	resp = append(resp, RegenerateResponse{Attempt: 1, Run: run, Eval: ev})

	if ev.NeedRetry {
		run, ev, err = h.operator.ValidateScriptRun(traceCtx, path)
		if err != nil {
			logger.Warn("failed to run script again", zap.Error(err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp = append(resp, RegenerateResponse{Attempt: 2, Run: run, Eval: ev})
	}

	handlerutil.WriteJSONResponse(w, http.StatusOK, resp)
}
