package grafana

import (
    "context"
    "fmt"
    "net/http"
    "time"

    handlerutil "github.com/NYCU-SDC/summer/pkg/handler"
    logutil "github.com/NYCU-SDC/summer/pkg/log"
    "github.com/NYCU-SDC/summer/pkg/problem"
    "github.com/go-playground/validator/v10"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/trace"
    "go.uber.org/zap"
)

type Store interface {
	Collect(ctx context.Context, startAt string) error
}

type Request struct {
    // Status     string `json:"status"`
    StartAt  string `json:"start_at" validate:"required"`
}

type Handler struct {
    logger        *zap.Logger
    validator     *validator.Validate
    problemWriter *problem.HttpWriter
    store         Store
    tracer        trace.Tracer
}

func NewHandler(logger *zap.Logger, validator *validator.Validate, problemWriter *problem.HttpWriter, store Store) *Handler {
    return &Handler{
        logger:        logger,
        validator:     validator,
        problemWriter: problemWriter,
        store:         store,
        tracer:        otel.Tracer("grafana/handler"),
    }
}

// CollectHandler handles POST requests for analysis
func (h *Handler) CollectHandler(w http.ResponseWriter, r *http.Request) {
    traceCtx, span := h.tracer.Start(r.Context(), "CollectHandler")
    defer span.End()
    logger := logutil.WithContext(traceCtx, h.logger)

    // Parse and validate request body
    var req Request
    err := handlerutil.ParseAndValidateRequestBody(traceCtx, h.validator, r, &req)
    if err != nil {
        h.problemWriter.WriteError(traceCtx, w, err, logger)
        return
    }

    logger.Info("Starting data collection", zap.Any("request", req))

    // Set timeout to prevent long-running Python scripts from blocking the server
    ctx, cancel := context.WithTimeout(traceCtx, 60*time.Second)
    defer cancel()

    // Call the service
    err = h.store.Collect(ctx, req.StartAt)
    if err != nil {
        h.problemWriter.WriteError(traceCtx, w, fmt.Errorf("data collection failed: %w", err), logger)
        return
    }

    logger.Info("Data collection completed successfully")

    handlerutil.WriteJSONResponse(w, http.StatusOK, nil)
}