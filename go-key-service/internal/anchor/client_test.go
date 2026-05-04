package anchor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFakeEVMClient_RecordsCalls(t *testing.T) {
	c := NewFakeEVMClient()
	root := newRoot(0xa1)
	r, err := c.Commit(context.Background(), 1, root, time.Unix(1, 0))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if r.ID != 0 {
		t.Errorf("first id should be 0, got %d", r.ID)
	}
	if r.TxHash == "" {
		t.Errorf("synthetic tx hash should be set")
	}
	if got := c.Calls(); got != 1 {
		t.Errorf("call counter: got %d want 1", got)
	}
}

func TestFakeEVMClient_MonotonicEnforced(t *testing.T) {
	c := NewFakeEVMClient()
	root := newRoot(0xa1)
	if _, err := c.Commit(context.Background(), 5, root, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Commit(context.Background(), 4, root, time.Unix(2, 0)); !errors.Is(err, ErrTreeShrank) {
		t.Errorf("expected ErrTreeShrank, got %v", err)
	}
	if _, err := c.Commit(context.Background(), 5, root, time.Unix(2, 0)); !errors.Is(err, ErrTreeShrank) {
		t.Errorf("equal-size commit should also shrink, got %v", err)
	}
}

func TestFakeEVMClient_InvalidInputs(t *testing.T) {
	c := NewFakeEVMClient()
	if _, err := c.Commit(context.Background(), 0, newRoot(0xa1), time.Now()); !errors.Is(err, ErrEmptyTree) {
		t.Errorf("expected ErrEmptyTree, got %v", err)
	}
	if _, err := c.Commit(context.Background(), 1, []byte{0x1}, time.Now()); !errors.Is(err, ErrInvalidRoot) {
		t.Errorf("expected ErrInvalidRoot, got %v", err)
	}
}

func TestFakeEVMClient_OneShotErrorClears(t *testing.T) {
	c := NewFakeEVMClient()
	want := errors.New("network down")
	c.SetNextError(want)
	if _, err := c.Commit(context.Background(), 1, newRoot(0xa1), time.Now()); !errors.Is(err, want) {
		t.Errorf("expected armed error, got %v", err)
	}
	// Second call should succeed — the arming is one-shot.
	if _, err := c.Commit(context.Background(), 2, newRoot(0xa1), time.Now()); err != nil {
		t.Errorf("expected success after one-shot error, got %v", err)
	}
}

func TestNewCastClient_ValidatesConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  CastClientConfig
	}{
		{"missing contract", CastClientConfig{RPCURL: "http://x", PrivateKey: "0x1"}},
		{"missing rpc", CastClientConfig{ContractAddress: "0xa", PrivateKey: "0x1"}},
		{"missing key", CastClientConfig{ContractAddress: "0xa", RPCURL: "http://x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCastClient(tc.cfg); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestCastClient_BuildsCommandAndParsesReceipt(t *testing.T) {
	c, err := NewCastClient(CastClientConfig{
		ContractAddress: "0xCAFE",
		RPCURL:          "http://localhost:8545",
		PrivateKey:      "0xab" + strings.Repeat("0", 62),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	var got struct {
		bin  string
		args []string
	}
	c.commandRunner = func(_ context.Context, name string, args ...string) ([]byte, error) {
		got.bin = name
		got.args = append(got.args, args...)
		return []byte(`{"transactionHash":"0xdead","blockNumber":"0x1a"}`), nil
	}

	receipt, err := c.Commit(context.Background(), 7, newRoot(0xa1), time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got.bin != "cast" {
		t.Errorf("binary: got %q want cast", got.bin)
	}
	// First arg is the subcommand.
	if got.args[0] != "send" {
		t.Errorf("first arg: got %q want send", got.args[0])
	}
	// Last three args are the abi-encoded calldata.
	n := len(got.args)
	if got.args[n-4] != "commit(uint64,bytes32,uint64)" {
		t.Errorf("function selector: got %q", got.args[n-4])
	}
	if got.args[n-3] != "7" {
		t.Errorf("size arg: got %q want 7", got.args[n-3])
	}
	if got.args[n-2] != "0x"+strings.Repeat("a1", 32) {
		t.Errorf("root arg: got %q", got.args[n-2])
	}
	if got.args[n-1] != "1700000000" {
		t.Errorf("ts arg: got %q want 1700000000", got.args[n-1])
	}
	if receipt.TxHash != "0xdead" {
		t.Errorf("tx hash: got %q", receipt.TxHash)
	}
	if receipt.BlockNumber != 26 {
		t.Errorf("block number: got %d want 26", receipt.BlockNumber)
	}
}

func TestCastClient_RejectsBadInputs(t *testing.T) {
	c, _ := NewCastClient(CastClientConfig{
		ContractAddress: "0xCAFE",
		RPCURL:          "http://localhost:8545",
		PrivateKey:      "0xab",
	})
	c.commandRunner = func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("commandRunner should not be invoked on validation failure")
		return nil, nil
	}
	if _, err := c.Commit(context.Background(), 0, newRoot(0xa1), time.Now()); !errors.Is(err, ErrEmptyTree) {
		t.Errorf("expected ErrEmptyTree, got %v", err)
	}
	if _, err := c.Commit(context.Background(), 1, []byte{0x1}, time.Now()); !errors.Is(err, ErrInvalidRoot) {
		t.Errorf("expected ErrInvalidRoot, got %v", err)
	}
}

func TestCastClient_SurfacesCastFailure(t *testing.T) {
	c, _ := NewCastClient(CastClientConfig{
		ContractAddress: "0xCAFE",
		RPCURL:          "http://localhost:8545",
		PrivateKey:      "0xab",
	})
	c.commandRunner = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("revert: TreeShrank"), errors.New("exit 1")
	}
	_, err := c.Commit(context.Background(), 1, newRoot(0xa1), time.Now())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "TreeShrank") {
		t.Errorf("error should include cast output: %v", err)
	}
}

func TestParseCastSendOutput_HandlesDecimalBlockNumber(t *testing.T) {
	r, err := parseCastSendOutput([]byte(`{"transactionHash":"0xab","blockNumber":"42"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.BlockNumber != 42 {
		t.Errorf("block number: got %d want 42", r.BlockNumber)
	}
}

func TestParseCastSendOutput_RejectsMissingHash(t *testing.T) {
	if _, err := parseCastSendOutput([]byte(`{"blockNumber":"0x1"}`)); err == nil {
		t.Fatal("expected error on missing tx hash")
	}
}

func TestParseCastSendOutput_RejectsBadJSON(t *testing.T) {
	if _, err := parseCastSendOutput([]byte("not json")); err == nil {
		t.Fatal("expected error on bad json")
	}
}
