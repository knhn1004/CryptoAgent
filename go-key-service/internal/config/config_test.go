package config

import (
	"log/slog"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("KEYSERVER_ADDR", "")
	t.Setenv("KEYSERVER_LOG_LEVEL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":8080" {
		t.Fatalf("Addr default: got %q want :8080", cfg.Addr)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Fatalf("LogLevel default: got %v want info", cfg.LogLevel)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("KEYSERVER_ADDR", "127.0.0.1:9090")
	t.Setenv("KEYSERVER_LOG_LEVEL", "debug")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "127.0.0.1:9090" {
		t.Fatalf("Addr override: got %q", cfg.Addr)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Fatalf("LogLevel override: got %v", cfg.LogLevel)
	}
}

func TestLoadInvalidLevel(t *testing.T) {
	t.Setenv("KEYSERVER_LOG_LEVEL", "loud")
	if _, err := Load(); err == nil {
		t.Fatal("expected error on invalid level")
	}
}
