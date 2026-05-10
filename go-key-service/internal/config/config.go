// Package config loads runtime settings from environment variables.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Secret is a string that hides its contents in String() / MarshalJSON
// outputs. Use it for fields that hold credentials so accidental log
// lines or JSON dumps of Config don't leak the value.
type Secret string

// String redacts the secret. The raw value is retrieved with Reveal.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return "[REDACTED]"
}

// GoString redacts the secret in fmt's %#v form too.
func (s Secret) GoString() string { return s.String() }

// MarshalJSON redacts on JSON marshal.
func (s Secret) MarshalJSON() ([]byte, error) {
	if s == "" {
		return []byte(`""`), nil
	}
	return []byte(`"[REDACTED]"`), nil
}

// Reveal returns the underlying value. Call only when handing the
// secret to the consumer (e.g. the anchor client constructor).
func (s Secret) Reveal() string { return string(s) }

// AnchorMode controls the anchor committer wiring.
type AnchorMode string

const (
	// AnchorOff disables on-chain anchoring entirely. Default.
	AnchorOff AnchorMode = "off"
	// AnchorDryRun runs the committer with the in-memory FakeEVMClient —
	// the indexer endpoint returns real anchors, but no transaction is
	// broadcast. Useful for the demo / dashboard wiring.
	AnchorDryRun AnchorMode = "dry-run"
	// AnchorCast runs the committer with the foundry `cast send` client.
	// Requires ANCHOR_CONTRACT_ADDRESS, ANCHOR_RPC_URL, ANCHOR_PRIVATE_KEY.
	AnchorCast AnchorMode = "cast"
)

type Config struct {
	Addr     string
	LogLevel slog.Level

	AnchorMode            AnchorMode
	AnchorInterval        time.Duration
	AnchorContractAddress string
	AnchorRPCURL          string
	AnchorPrivateKey      Secret
	AnchorCastBinary      string

	// CORSOrigins is the comma-separated allowlist of dashboard origins
	// (e.g. http://localhost:5173). Empty = CORS off.
	CORSOrigins []string
}

func Load() (Config, error) {
	cfg := Config{
		Addr:           getEnv("KEYSERVER_ADDR", ":8080"),
		LogLevel:       slog.LevelInfo,
		AnchorMode:     AnchorMode(strings.ToLower(getEnv("ANCHOR_MODE", string(AnchorOff)))),
		AnchorInterval: 15 * time.Minute,
		CORSOrigins:    parseOrigins(os.Getenv("KEYSERVER_CORS_ORIGINS")),
	}
	if raw := os.Getenv("KEYSERVER_LOG_LEVEL"); raw != "" {
		lvl, err := parseLevel(raw)
		if err != nil {
			return Config{}, err
		}
		cfg.LogLevel = lvl
	}
	if raw := os.Getenv("ANCHOR_INTERVAL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("config: ANCHOR_INTERVAL: %w", err)
		}
		if d <= 0 {
			return Config{}, fmt.Errorf("config: ANCHOR_INTERVAL must be > 0")
		}
		cfg.AnchorInterval = d
	}
	switch cfg.AnchorMode {
	case AnchorOff, AnchorDryRun:
		// nothing further to load
	case AnchorCast:
		cfg.AnchorContractAddress = os.Getenv("ANCHOR_CONTRACT_ADDRESS")
		cfg.AnchorRPCURL = os.Getenv("ANCHOR_RPC_URL")
		cfg.AnchorPrivateKey = Secret(os.Getenv("ANCHOR_PRIVATE_KEY"))
		cfg.AnchorCastBinary = os.Getenv("ANCHOR_CAST_BINARY")
		if cfg.AnchorContractAddress == "" || cfg.AnchorRPCURL == "" || cfg.AnchorPrivateKey == "" {
			return Config{}, fmt.Errorf(
				"config: ANCHOR_MODE=cast requires ANCHOR_CONTRACT_ADDRESS, ANCHOR_RPC_URL, ANCHOR_PRIVATE_KEY",
			)
		}
	default:
		return Config{}, fmt.Errorf("config: unknown ANCHOR_MODE %q", cfg.AnchorMode)
	}
	return cfg, nil
}

func parseOrigins(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
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
