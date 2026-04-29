// Package action defines the canonical agent action message and its
// deterministic encoding. See docs/schema.md for the full contract.
package action

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	SchemaVersion = 1
	NonceHexLen   = 32
	MaxSkewMillis = 30_000
	NonceWindowMs = 600_000
)

type Action struct {
	SchemaVersion int    `json:"schema_version"`
	AgentID       string `json:"agent_id"`
	ActionType    string `json:"action_type"`
	Target        string `json:"target"`
	TimestampMs   int64  `json:"timestamp"`
	Nonce         string `json:"nonce"`
}

var (
	ErrSchemaVersion = errors.New("action: unsupported schema_version")
	ErrEmptyField    = errors.New("action: required field empty")
	ErrNonceShape    = errors.New("action: nonce must be 32 lowercase hex chars")
)

// Validate checks structural invariants. Replay-window checks
// (timestamp skew, nonce reuse) are the verifier's job.
func (a *Action) Validate() error {
	if a.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: got %d want %d", ErrSchemaVersion, a.SchemaVersion, SchemaVersion)
	}
	if a.AgentID == "" || a.ActionType == "" || a.Target == "" {
		return ErrEmptyField
	}
	if len(a.Nonce) != NonceHexLen {
		return ErrNonceShape
	}
	if _, err := hex.DecodeString(a.Nonce); err != nil {
		return ErrNonceShape
	}
	for _, r := range a.Nonce {
		if r >= 'A' && r <= 'F' {
			return ErrNonceShape
		}
	}
	return nil
}

// Canonical returns the deterministic JSON bytes used for signing
// and hashing. Keys are sorted; no insignificant whitespace.
func (a *Action) Canonical() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	// encoding/json sorts map keys. Marshal via map to guarantee order
	// independent of struct field declaration order.
	m := map[string]any{
		"schema_version": a.SchemaVersion,
		"agent_id":       a.AgentID,
		"action_type":    a.ActionType,
		"target":         a.Target,
		"timestamp":      a.TimestampMs,
		"nonce":          a.Nonce,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	// Encoder appends a trailing newline; strip it.
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}
