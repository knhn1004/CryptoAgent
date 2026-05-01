// Package config loads runtime settings from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	Addr     string
	LogLevel slog.Level
}

func Load() (Config, error) {
	cfg := Config{
		Addr:     getEnv("KEYSERVER_ADDR", ":8080"),
		LogLevel: slog.LevelInfo,
	}
	if raw := os.Getenv("KEYSERVER_LOG_LEVEL"); raw != "" {
		lvl, err := parseLevel(raw)
		if err != nil {
			return Config{}, err
		}
		cfg.LogLevel = lvl
	}
	return cfg, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("config: unknown KEYSERVER_LOG_LEVEL %q", s)
}
