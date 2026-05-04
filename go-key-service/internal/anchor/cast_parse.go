package anchor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// parseCastSendOutput pulls the bits we care about out of `cast send
// --json`. The receipt shape is the standard JSON-RPC eth_getTransactionReceipt
// payload, with hex-encoded uint fields.
//
// We do not import go-ethereum just to decode this — the field set is
// stable and small.
func parseCastSendOutput(raw []byte) (CommitReceipt, error) {
	var r struct {
		TransactionHash string `json:"transactionHash"`
		BlockNumber     string `json:"blockNumber"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return CommitReceipt{}, fmt.Errorf("decode json: %w", err)
	}
	if r.TransactionHash == "" {
		return CommitReceipt{}, fmt.Errorf("receipt missing transactionHash")
	}
	bn, err := parseHexUint(r.BlockNumber)
	if err != nil {
		return CommitReceipt{}, fmt.Errorf("blockNumber: %w", err)
	}
	return CommitReceipt{
		TxHash:      r.TransactionHash,
		BlockNumber: bn,
	}, nil
}

// parseHexUint accepts "0x1a" or "26" and returns 26. cast usually
// emits 0x-prefixed hex but tests/older versions sometimes emit
// decimal — handle both.
func parseHexUint(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}
