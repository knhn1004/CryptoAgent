package auditloghttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/auditlog"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/merkle"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/signing"
)

func makeAction(agentID string, tsMs int64, nonce string) *action.Action {
	return &action.Action{
		SchemaVersion: action.SchemaVersion,
		AgentID:       agentID,
		ActionType:    "ping",
		Target:        "peer-002",
		TimestampMs:   tsMs,
		Nonce:         nonce,
	}
}

func newHarness(t *testing.T) (http.Handler, *auditlog.Pipeline, keystore.KeyStore, time.Time) {
	t.Helper()
	now := time.UnixMilli(1_700_000_000_000)
	store := keystore.NewMemory()
	tree := merkle.New()
	p := auditlog.New(tree, store, auditlog.WithClock(func() time.Time { return now }))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return Handler(p, logger), p, store, now
}

func registerAgent(t *testing.T, store keystore.KeyStore, id string) (pub, priv []byte) {
	t.Helper()
	if _, err := store.Create(context.Background(), id); err != nil {
		t.Fatalf("create: %v", err)
	}
	p, k, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return p, k
}

func TestAppendHappyPath(t *testing.T) {
	h, _, store, now := newHarness(t)
	_, priv := registerAgent(t, store, "agent-1")

	a := makeAction("agent-1", now.UnixMilli(), "0123456789abcdef0123456789abcdef")
	sig, err := signing.Sign(a, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"action":    a,
		"signature": hex.EncodeToString(sig),
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body.String())
	}
	if got["idempotent"] != false {
		t.Fatalf("idempotent: got %v want false", got["idempotent"])
	}
	if got["leaf_index"].(float64) != 0 {
		t.Fatalf("leaf_index: got %v want 0", got["leaf_index"])
	}
	if got["leaf_hash"] == "" {
		t.Fatal("leaf_hash empty")
	}
}

func TestAppendDuplicateReturnsIdempotent(t *testing.T) {
	h, _, store, now := newHarness(t)
	_, priv := registerAgent(t, store, "agent-1")

	a := makeAction("agent-1", now.UnixMilli(), "0123456789abcdef0123456789abcdef")
	sig, _ := signing.Sign(a, priv)
	body, _ := json.Marshal(map[string]any{
		"action":    a,
		"signature": hex.EncodeToString(sig),
	})

	req1 := httptest.NewRequest(http.MethodPost, "/v1/audit/append", bytes.NewReader(body))
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first status: %d body=%s", rec1.Code, rec1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/v1/audit/append", bytes.NewReader(body))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("dup status: %d", rec2.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["idempotent"] != true {
		t.Fatalf("idempotent: got %v want true", got["idempotent"])
	}
}

func TestAppendBadSignature(t *testing.T) {
	h, _, store, now := newHarness(t)
	registerAgent(t, store, "agent-1")

	a := makeAction("agent-1", now.UnixMilli(), "0123456789abcdef0123456789abcdef")
	bad := bytes.Repeat([]byte{0xAA}, 64)
	body, _ := json.Marshal(map[string]any{
		"action":    a,
		"signature": hex.EncodeToString(bad),
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401, body=%s", rec.Code, rec.Body.String())
	}
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env["error"] != "invalid_signature" {
		t.Fatalf("error code: %v", env["error"])
	}
}

func TestAppendUnknownAgent(t *testing.T) {
	h, _, store, now := newHarness(t)
	_, priv := registerAgent(t, store, "agent-other")

	a := makeAction("agent-missing", now.UnixMilli(), "0123456789abcdef0123456789abcdef")
	sig, _ := signing.Sign(a, priv)
	body, _ := json.Marshal(map[string]any{
		"action":    a,
		"signature": hex.EncodeToString(sig),
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAppendBadJSON(t *testing.T) {
	h, _, _, _ := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/audit/append", bytes.NewReader([]byte("not-json")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestEventStreamReplaysAndTails(t *testing.T) {
	h, p, store, now := newHarness(t)
	_, priv := registerAgent(t, store, "agent-1")

	// Pre-populate two events so the stream has history to replay.
	for i, nonce := range []string{
		"00000000000000000000000000000001",
		"00000000000000000000000000000002",
	} {
		a := makeAction("agent-1", now.UnixMilli(), nonce)
		sig, _ := signing.Sign(a, priv)
		if _, _, err := p.Submit(context.Background(), a, sig); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/v1/audit/events?since=0", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status: %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type: %q", ct)
	}

	rd := bufio.NewReader(resp.Body)
	got := readSSEEvents(t, rd, 2)
	if len(got) != 2 {
		t.Fatalf("replay: got %d want 2", len(got))
	}
	if got[0]["leaf_index"].(float64) != 0 || got[1]["leaf_index"].(float64) != 1 {
		t.Fatalf("replay order: %+v", got)
	}

	// Push a live event and read it from the stream.
	a := makeAction("agent-1", now.UnixMilli(), "00000000000000000000000000000003")
	sig, _ := signing.Sign(a, priv)
	if _, _, err := p.Submit(context.Background(), a, sig); err != nil {
		t.Fatalf("live submit: %v", err)
	}
	live := readSSEEvents(t, rd, 1)
	if len(live) != 1 || live[0]["leaf_index"].(float64) != 2 {
		t.Fatalf("live: %+v", live)
	}
}

// readSSEEvents reads up to n SSE `data:` events from rd, with a per-event
// timeout. It assumes one JSON object per `data:` line and a blank line
// delimiter between events.
func readSSEEvents(t *testing.T, rd *bufio.Reader, n int) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, n)
	type line struct {
		s   string
		err error
	}
	deadline := time.After(3 * time.Second)
	lineCh := make(chan line, 1)

	for len(out) < n {
		go func() {
			s, err := rd.ReadString('\n')
			lineCh <- line{s, err}
		}()
		select {
		case ln := <-lineCh:
			if ln.err != nil {
				t.Fatalf("read: %v", ln.err)
			}
			s := strings.TrimRight(ln.s, "\r\n")
			if !strings.HasPrefix(s, "data:") {
				continue
			}
			payload := strings.TrimSpace(strings.TrimPrefix(s, "data:"))
			var m map[string]any
			if err := json.Unmarshal([]byte(payload), &m); err != nil {
				t.Fatalf("sse json: %v line=%q", err, payload)
			}
			out = append(out, m)
		case <-deadline:
			t.Fatalf("timeout waiting for %d events; got %d", n, len(out))
		}
	}
	return out
}
