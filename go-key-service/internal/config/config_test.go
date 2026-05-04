package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
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

func TestAnchorDefaultsOff(t *testing.T) {
	t.Setenv("ANCHOR_MODE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AnchorMode != AnchorOff {
		t.Errorf("AnchorMode default: got %q want %q", cfg.AnchorMode, AnchorOff)
	}
}

func TestAnchorDryRunNeedsNothing(t *testing.T) {
	t.Setenv("ANCHOR_MODE", "dry-run")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AnchorMode != AnchorDryRun {
		t.Errorf("AnchorMode: got %q want dry-run", cfg.AnchorMode)
	}
}

func TestAnchorCastRequiresAllFields(t *testing.T) {
	t.Setenv("ANCHOR_MODE", "cast")
	t.Setenv("ANCHOR_CONTRACT_ADDRESS", "")
	t.Setenv("ANCHOR_RPC_URL", "")
	t.Setenv("ANCHOR_PRIVATE_KEY", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected error on missing cast fields")
	}
	t.Setenv("ANCHOR_CONTRACT_ADDRESS", "0xabc")
	t.Setenv("ANCHOR_RPC_URL", "http://localhost:8545")
	t.Setenv("ANCHOR_PRIVATE_KEY", "0xdead")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("expected success with all fields, got %v", err)
	}
	if cfg.AnchorContractAddress != "0xabc" {
		t.Errorf("contract address not loaded")
	}
}

func TestAnchorIntervalParsed(t *testing.T) {
	t.Setenv("ANCHOR_MODE", "dry-run")
	t.Setenv("ANCHOR_INTERVAL", "30s")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AnchorInterval.String() != "30s" {
		t.Errorf("AnchorInterval: got %v want 30s", cfg.AnchorInterval)
	}
}

func TestAnchorRejectsUnknownMode(t *testing.T) {
	t.Setenv("ANCHOR_MODE", "lunar")
	if _, err := Load(); err == nil {
		t.Fatal("expected error on unknown anchor mode")
	}
}

func TestSecretRedactsInString(t *testing.T) {
	s := Secret("0xdeadbeef")
	if got := s.String(); got == "0xdeadbeef" {
		t.Errorf("String() leaked the secret: %q", got)
	}
	if got := fmt.Sprintf("%v", s); strings.Contains(got, "deadbeef") {
		t.Errorf("%%v leaked the secret: %q", got)
	}
	if got := fmt.Sprintf("%#v", s); strings.Contains(got, "deadbeef") {
		t.Errorf("%%#v leaked the secret: %q", got)
	}
	if Secret("").String() != "" {
		t.Errorf("empty secret should stringify as empty")
	}
}

func TestSecretRedactsInJSON(t *testing.T) {
	type holder struct {
		Key Secret `json:"key"`
	}
	out, err := json.Marshal(holder{Key: Secret("0xdeadbeef")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "deadbeef") {
		t.Errorf("MarshalJSON leaked the secret: %s", out)
	}
}

func TestSecretReveal(t *testing.T) {
	s := Secret("0xdeadbeef")
	if s.Reveal() != "0xdeadbeef" {
		t.Errorf("Reveal() should return raw value")
	}
}
