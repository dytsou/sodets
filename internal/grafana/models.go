package grafana

type ScriptInput struct {
    Labels       map[string]string `json:"labels"`
    TimeRange    TimeRange         `json:"time_range"`
    ScanSettings ScanSettings      `json:"scan_settings"`
    OutputDirectory string         `json:"output_directory"`
}

type TimeRange struct {
    Start string `json:"start"`
    End   string `json:"end"`
}

type ScanSettings struct {
    ContextWindowSeconds int `json:"context_window_seconds"`
    MaxConcurrentTasks   int `json:"max_concurrent_tasks"`
}