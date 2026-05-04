package anchorhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/anchor"
)

func TestLatest_404WhenEmpty(t *testing.T) {
	store := anchor.NewLatestStore()
	srv := httptest.NewServer(Handler(store, nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/anchor/latest")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", resp.StatusCode)
	}
}

func TestLatest_ReturnsLatestAnchor(t *testing.T) {
	store := anchor.NewLatestStore()
	root := make([]byte, anchor.HashSize)
	for i := range root {
		root[i] = 0xab
	}
	store.Set(anchor.Anchor{
		ID:          7,
		TreeSize:    42,
		Root:        root,
		Timestamp:   time.UnixMilli(1_700_000_000_500).UTC(),
		BlockNumber: 12345,
		TxHash:      "0xdeadbeef",
	})

	srv := httptest.NewServer(Handler(store, nil))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/anchor/latest")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["tree_size"].(float64) != 42 {
		t.Errorf("tree_size: got %v want 42", body["tree_size"])
	}
	if body["root_hex"] != "0x"+strings.Repeat("ab", 32) {
		t.Errorf("root_hex: got %v", body["root_hex"])
	}
	if body["block_number"].(float64) != 12345 {
		t.Errorf("block_number: got %v", body["block_number"])
	}
	if body["tx_hash"] != "0xdeadbeef" {
		t.Errorf("tx_hash: got %v", body["tx_hash"])
	}
	if body["timestamp_ms"].(float64) != 1_700_000_000_500 {
		t.Errorf("timestamp_ms: got %v", body["timestamp_ms"])
	}
}
