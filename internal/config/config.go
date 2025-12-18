package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	configutil "github.com/NYCU-SDC/summer/pkg/config"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const DefaultSecret = "default-secret"

type Config struct {
	// Dev mode disables strict cookie policies by using SameSite=None
	// instead of SameSite=Strict, allowing cross-site requests during development.
	Dev                       bool          `yaml:"dev"                envconfig:"DEV"`
	Debug                     bool          `yaml:"debug"              envconfig:"DEBUG"`
	Host                      string        `yaml:"host"               envconfig:"HOST"`
	Port                      string        `yaml:"port"               envconfig:"PORT"`
	BaseURL                   string        `yaml:"base_url"          envconfig:"BASE_URL"`
	OauthProxyBaseURL         string        `yaml:"oauth_proxy_base_url" envconfig:"OAUTH_PROXY_BASE_URL"`
	OauthProxySecret          string        `yaml:"oauth_proxy_secret" envconfig:"OAUTH_PROXY_SECRET"`
	Secret                    string        `yaml:"secret"             envconfig:"SECRET"`
	AccessTokenExpirationStr  string        `yaml:"access_token_expiration" envconfig:"ACCESS_TOKEN_EXPIRATION"`
	RefreshTokenExpirationStr string        `yaml:"refresh_token_expiration" envconfig:"REFRESH_TOKEN_EXPIRATION"`
	OtelCollectorUrl          string        `yaml:"otel_collector_url" envconfig:"OTEL_COLLECTOR_URL"`
	AllowOrigins              []string      `yaml:"allow_origins"      envconfig:"ALLOW_ORIGINS"`
	GeminiAPIKey              string        `yaml:"gemini_api_key"      envconfig:"GEMINI_API_KEY"`
	ErrLogPath                string        `yaml:"err_log_path"   envconfig:"ERR_LOG_PATH"`
	AccessTokenExpiration     time.Duration `yaml:"-"`
	RefreshTokenExpiration    time.Duration `yaml:"-"`
	PythonPath                string        `yaml:"python_path"        envconfig:"PYTHON_PATH"`
	GrafanaScriptPath         string        `yaml:"grafana_script_path" envconfig:"GRAFANA_SCRIPT_PATH"`
	ObservabilityDataPath     string        `yaml:"observability_data_path" envconfig:"OBSERVABILITY_DATA_PATH"`

}

type LogBuffer struct {
	buffer []logEntry
}

type logEntry struct {
	msg  string
	err  error
	meta map[string]string
}

func NewConfigLogger() *LogBuffer {
	return &LogBuffer{}
}

func (cl *LogBuffer) Warn(msg string, err error, meta map[string]string) {
	cl.buffer = append(cl.buffer, logEntry{msg: msg, err: err, meta: meta})
}

func (cl *LogBuffer) FlushToZap(logger *zap.Logger) {
	for _, e := range cl.buffer {
		var fields []zap.Field
		if e.err != nil {
			fields = append(fields, zap.Error(e.err))
		}
		for k, v := range e.meta {
			fields = append(fields, zap.String(k, v))
		}
		logger.Warn(e.msg, fields...)
	}
	cl.buffer = nil
}

func (c *Config) Validate() error {
	var err error

	// Parse access_token_expiration string into time.Duration
	if c.AccessTokenExpirationStr != "" {
		c.AccessTokenExpiration, err = time.ParseDuration(c.AccessTokenExpirationStr)
		if err != nil {
			return fmt.Errorf("invalid access_token_expiration: %w", err)
		}
		if c.AccessTokenExpiration <= 0 {
			return fmt.Errorf("access_token_expiration must be greater than zero")
		}
	}

	// Parse refresh_token_expiration string into time.Duration
	if c.RefreshTokenExpirationStr != "" {
		c.RefreshTokenExpiration, err = time.ParseDuration(c.RefreshTokenExpirationStr)
		if err != nil {
			return fmt.Errorf("invalid refresh_token_expiration: %w", err)
		}
		if c.RefreshTokenExpiration <= 0 {
			return fmt.Errorf("refresh_token_expiration must be greater than zero")
		}
	}

	if c.OauthProxyBaseURL != "" && c.OauthProxySecret == "" {
		return fmt.Errorf("oauth_proxy_secret must be set when oauth_proxy_base_url is provided")
	} else if c.OauthProxyBaseURL == "" && c.OauthProxySecret == "" {
		c.OauthProxySecret = uuid.New().String()
	}

	// Optional: Warn if duration is too long to be practical for cookie MaxAge
	const maxReasonableCookieAge = 10 * 365 * 24 * time.Hour
	if c.AccessTokenExpiration > maxReasonableCookieAge {
		zap.L().Warn("AccessTokenExpiration is unusually long for cookie MaxAge", zap.Duration("duration", c.AccessTokenExpiration))
	}

	return nil
}

func Load() (Config, *LogBuffer) {
	logger := NewConfigLogger()

	config := &Config{
		Debug:                     false,
		Dev:                       false,
		Host:                      "0.0.0.0",
		Port:                      "8081",
		Secret:                    DefaultSecret,
		AccessTokenExpirationStr:  "15m",
		RefreshTokenExpirationStr: "720h",
		OtelCollectorUrl:          "",
		GeminiAPIKey:              "",
		ErrLogPath:                "",
		PythonPath:                "python3",
		GrafanaScriptPath:         "/app/collector/main.py",
		ObservabilityDataPath:     "/app/observability-data",
	}

	var err error

	config, err = FromFile("config.yaml", config, logger)
	if err != nil {
		logger.Warn("Failed to load config from file", err, map[string]string{"path": "config.yaml"})
	}

	config, err = FromEnv(config, logger)
	if err != nil {
		logger.Warn("Failed to load config from env", err, map[string]string{"path": ".env"})
	}

	config, err = FromFlags(config)
	if err != nil {
		logger.Warn("Failed to load config from flags", err, map[string]string{"path": "flags"})
	}

	return *config, logger
}

func FromFile(filePath string, config *Config, logger *LogBuffer) (*Config, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return config, err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			logger.Warn("Failed to close config file", err, map[string]string{"path": filePath})
		}
	}(file)

	fileConfig := Config{}
	if err := yaml.NewDecoder(file).Decode(&fileConfig); err != nil {
		return config, err
	}

	return configutil.Merge[Config](config, &fileConfig)
}

func FromEnv(config *Config, logger *LogBuffer) (*Config, error) {
	if err := godotenv.Overload(); err != nil {
		if os.IsNotExist(err) {
			logger.Warn("No .env file found", err, map[string]string{"path": ".env"})
		} else {
			return nil, err
		}
	}

	// Allow origins
	allowOrigins := os.Getenv("ALLOW_ORIGINS")
	if allowOrigins != "" {
		config.AllowOrigins = strings.Split(allowOrigins, ",")
	}

	envConfig := &Config{
		Debug:             os.Getenv("DEBUG") == "true",
		Dev:               os.Getenv("DEV") == "true",
		Host:              os.Getenv("HOST"),
		Port:              os.Getenv("PORT"),
		BaseURL:           os.Getenv("BASE_URL"),
		OauthProxyBaseURL: os.Getenv("OAUTH_PROXY_BASE_URL"),
		OauthProxySecret:  os.Getenv("OAUTH_PROXY_SECRET"),
		Secret:            os.Getenv("SECRET"),
		OtelCollectorUrl:  os.Getenv("OTEL_COLLECTOR_URL"),
		GeminiAPIKey:      os.Getenv("GEMINI_API_KEY"),
		PythonPath:     os.Getenv("PYTHON_PATH"),
		GrafanaScriptPath: os.Getenv("GRAFANA_SCRIPT_PATH"),
		ObservabilityDataPath: os.Getenv("OBSERVABILITY_DATA_PATH"),
	}

	return configutil.Merge[Config](config, envConfig)
}

func FromFlags(config *Config) (*Config, error) {
	flagConfig := &Config{}

	flag.BoolVar(&flagConfig.Debug, "debug", false, "debug mode")
	flag.BoolVar(&flagConfig.Dev, "dev", false, "dev mode")
	flag.StringVar(&flagConfig.Host, "host", "", "host")
	flag.StringVar(&flagConfig.Port, "port", "", "port")
	flag.StringVar(&flagConfig.BaseURL, "base_url", "", "base url")
	flag.StringVar(&flagConfig.Secret, "secret", "", "secret")
	flag.StringVar(&flagConfig.OtelCollectorUrl, "otel_collector_url", "", "OpenTelemetry collector URL")
	flag.StringVar(&flagConfig.GeminiAPIKey, "gemini_api_key", "", "Gemini API key")
	flag.StringVar(&flagConfig.PythonPath, "python_path", "", "Path to the Python interpreter")
	flag.StringVar(&flagConfig.GrafanaScriptPath, "grafana_script_path", "", "Path to the Grafana analysis script")
	flag.StringVar(&flagConfig.ObservabilityDataPath, "observability_data_path", "", "Path to store observability data")

	flag.Parse()

	return configutil.Merge[Config](config, flagConfig)
}
