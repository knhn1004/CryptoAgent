// Package capability issues, verifies, and revokes scoped capability
// tokens. A token authorizes a specific agent to perform a bounded set
// of (action_type, target) pairs until expiry.
package capability

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
)

// Wildcard matches any value when present in Token.ActionTypes or
// Token.Targets. The literal "*" string is the only special case; no
// glob expansion is performed.
const Wildcard = "*"

// Token is the claim set the service signs. The detached Ed25519
// signature lives separately on the wire.
type Token struct {
	TokenID     string   `json:"token_id"`
	AgentID     string   `json:"agent_id"`
	ActionTypes []string `json:"action_types"`
	Targets     []string `json:"targets"`
	IssuedAt    int64    `json:"issued_at"`
	ExpiresAt   int64    `json:"expires_at"`
}

// Canonical returns the deterministic JSON bytes used for signing.
// Keys are sorted (encoding/json sorts map keys); list entries are
// sorted; no insignificant whitespace.
func (t *Token) Canonical() ([]byte, error) {
	actionTypes := append([]string(nil), t.ActionTypes...)
	sort.Strings(actionTypes)
	targets := append([]string(nil), t.Targets...)
	sort.Strings(targets)
	m := map[string]any{
		"token_id":     t.TokenID,
		"agent_id":     t.AgentID,
		"action_types": actionTypes,
		"targets":      targets,
		"issued_at":    t.IssuedAt,
		"expires_at":   t.ExpiresAt,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}

// Allows reports whether actionType and target both satisfy the token's
// scope (exact match or Wildcard).
func (t *Token) Allows(actionType, target string) (actionOK, targetOK bool) {
	return contains(t.ActionTypes, actionType), contains(t.Targets, target)
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == Wildcard || v == want {
			return true
		}
	}
	return false
}

var (
	ErrMalformedToken       = errors.New("capability: malformed token")
	ErrInvalidSignature     = errors.New("capability: invalid signature")
	ErrExpired              = errors.New("capability: token expired")
	ErrRevoked              = errors.New("capability: token revoked")
	ErrAgentMismatch        = errors.New("capability: agent_id does not match token")
	ErrActionTypeNotAllowed = errors.New("capability: action_type not allowed by token")
	ErrTargetNotAllowed     = errors.New("capability: target not allowed by token")
	ErrUnknownAgent         = errors.New("capability: unknown agent")
	ErrInvalidTTL           = errors.New("capability: ttl_seconds must be > 0")
)
