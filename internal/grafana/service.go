package grafana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	logutil "github.com/NYCU-SDC/summer/pkg/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	logger     *zap.Logger
	tracer     trace.Tracer
	scriptPath string
	pythonExec string
	outputDir  string
}

func NewService(logger *zap.Logger, pythonPath, scriptPath, outputDir string) *Service {
	return &Service{
		logger:     logger,
		tracer:     otel.Tracer("grafana/service"),
		pythonExec: pythonPath,
		scriptPath: scriptPath,
		outputDir:  outputDir,
	}
}

func toScriptInput(endAtStr string, outputDir string) (ScriptInput, error) {
	if endAtStr == "" {
		return ScriptInput{}, fmt.Errorf("end_at time cannot be empty")
	}

	endTime, err := time.Parse(time.RFC3339, endAtStr)
	if err != nil {
		return ScriptInput{}, fmt.Errorf("invalid time format: %w", err)
	}

	startTime := endTime.Add(-5 * time.Second)

	return ScriptInput{
		Labels: map[string]string{
			"service_name": "core-system-backend",
		},
		TimeRange: TimeRange{
			Start: startTime.Format(time.RFC3339),
			End:   endTime.Format(time.RFC3339),
		},
		ScanSettings: ScanSettings{
			ContextWindowSeconds: 1,
			MaxConcurrentTasks:   5,
		},
		OutputDirectory: outputDir,
	}, nil
}

func (s *Service) Collect(ctx context.Context, endAt string) (*ScriptOutput, error) {
	traceCtx, span := s.tracer.Start(ctx, "Collect")
	defer span.End()
	logger := logutil.WithContext(traceCtx, s.logger)

	logger.Info("starting python script execution",
		zap.String("script_path", s.scriptPath),
		zap.String("python_exec", s.pythonExec),
		zap.String("end_at", endAt),
	)

	input, err := toScriptInput(endAt, s.outputDir)
	if err != nil {
		logger.Error("failed to generate script input", zap.Error(err))
		span.RecordError(err)
		return nil, err
	}

	cmd := exec.CommandContext(traceCtx, s.pythonExec, s.scriptPath)

	inputBytes, err := json.Marshal(input)
	if err != nil {
		logger.Error("failed to marshal input", zap.Error(err))
		span.RecordError(err)
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}

	logger.Info("marshalled input data",
		zap.Int("input_size", len(inputBytes)),
		zap.String("payload", string(inputBytes)),
	)

	cmd.Stdin = bytes.NewReader(inputBytes)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Info("executing python script")
	if err := cmd.Run(); err != nil {
		stdoutStr := stdout.String()
		stderrStr := stderr.String()

		logger.Error("python script execution failed",
			zap.Error(err),
			zap.String("stdout", stdoutStr),
			zap.String("stderr", stderrStr),
		)
		span.RecordError(err)
		return nil, fmt.Errorf("python script execution failed: %s, stderr: %s", err, stderrStr)
	}

	stdoutStr := stdout.String()
	if len(stdoutStr) > 0 {
		logger.Info("python script output (stdout)", zap.String("stdout", stdoutStr))
	}

	// Parse JSON output from stdout
	var scriptOutput ScriptOutput
	if err := json.Unmarshal([]byte(stdoutStr), &scriptOutput); err != nil {
		logger.Error("failed to parse script output",
			zap.Error(err),
			zap.String("stdout", stdoutStr),
		)
		span.RecordError(err)
		return nil, fmt.Errorf("failed to parse script output: %w", err)
	}

	logger.Info("python script executed successfully",
		zap.String("output_file", scriptOutput.OutputFile),
	)

	return &scriptOutput, nil
}