package anchor

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FakeEVMClient is the in-memory EVMClient used by tests and by the
// keyserver in `--anchor-mode=dry-run`. It enforces the same
// monotonicity invariant the contract does so the dashboard shows the
// same shape locally as it does on Sepolia.
type FakeEVMClient struct {
	mu       sync.Mutex
	anchors  []Anchor
	nextID   uint64
	failNext error
	calls    atomic.Int64
}

// NewFakeEVMClient returns an empty FakeEVMClient.
func NewFakeEVMClient() *FakeEVMClient { return &FakeEVMClient{} }

// SetNextError makes the next Commit call return err. One-shot; the
// arming clears after the call returns.
func (f *FakeEVMClient) SetNextError(err error) {
	f.mu.Lock()
	f.failNext = err
	f.mu.Unlock()
}

// Calls returns how many times Commit has been invoked. Useful for
// asserting "exactly one commit per growing tick".
func (f *FakeEVMClient) Calls() int64 { return f.calls.Load() }

// Anchors returns a copy of the recorded anchors in order.
func (f *FakeEVMClient) Anchors() []Anchor {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Anchor, len(f.anchors))
	copy(out, f.anchors)
	return out
}

// Commit implements EVMClient. Stores the anchor in memory; returns a
// synthetic receipt with a monotonic id and a zero block number.
func (f *FakeEVMClient) Commit(_ context.Context, treeSize uint64, root []byte, ts time.Time) (CommitReceipt, error) {
	f.calls.Add(1)
	if err := validateCommit(treeSize, root); err != nil {
		return CommitReceipt{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failNext; err != nil {
		f.failNext = nil
		return CommitReceipt{}, err
	}
	if n := len(f.anchors); n > 0 && treeSize <= f.anchors[n-1].TreeSize {
		return CommitReceipt{}, fmt.Errorf("%w: %d <= last %d", ErrTreeShrank, treeSize, f.anchors[n-1].TreeSize)
	}
	id := f.nextID
	f.nextID++
	a := Anchor{
		ID:        id,
		TreeSize:  treeSize,
		Root:      append([]byte(nil), root...),
		Timestamp: ts,
		TxHash:    fmt.Sprintf("0xfake%016x", id),
	}
	f.anchors = append(f.anchors, a)
	return CommitReceipt{ID: id, TxHash: a.TxHash}, nil
}

// CastClient is the production EVMClient: it shells out to the
// foundry `cast send` binary so the Go service does not have to pull
// go-ethereum into its dependency closure. Configuration is read from
// the process env at construction time so the broadcaster never logs
// the private key.
//
// The private key is passed to `cast` via the ETH_PRIVATE_KEY env var
// (which `cast send` accepts as a fallback when --private-key is
// absent), not via the command line. That keeps the secret out of
// `ps aux`, /proc/<pid>/cmdline, and shell history files.
//
// The contract ABI we target:
//
//	function commit(uint64 treeSize, bytes32 root, uint64 timestamp)
//	    external returns (uint256 id);
type CastClient struct {
	contract      string // 0x… address of the deployed AuditAnchor
	rpcURL        string
	privateKey    string // hex (0x-prefixed); never logged or argv-passed
	castBin       string // path to `cast` binary; "cast" if on PATH
	commandRunner func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)
}

// CastClientConfig carries the wiring CastClient needs.
type CastClientConfig struct {
	ContractAddress string
	RPCURL          string
	PrivateKey      string
	CastBinary      string // optional override; defaults to "cast"
}

// NewCastClient validates config and returns a ready client. It does
// not exec anything; the first network round-trip happens on Commit.
func NewCastClient(cfg CastClientConfig) (*CastClient, error) {
	if cfg.ContractAddress == "" {
		return nil, errors.New("anchor: ContractAddress is required")
	}
	if cfg.RPCURL == "" {
		return nil, errors.New("anchor: RPCURL is required")
	}
	if cfg.PrivateKey == "" {
		return nil, errors.New("anchor: PrivateKey is required")
	}
	bin := cfg.CastBinary
	if bin == "" {
		bin = "cast"
	}
	return &CastClient{
		contract:      cfg.ContractAddress,
		rpcURL:        cfg.RPCURL,
		privateKey:    cfg.PrivateKey,
		castBin:       bin,
		commandRunner: defaultCastRunner,
	}, nil
}

// Commit broadcasts a `commit(treeSize, root, ts)` transaction via
// `cast send` and parses the resulting JSON receipt for the tx hash
// and block number. The on-chain anchor id is read back from the
// `AuditAnchored` event the contract emits — for the demo we settle
// for the receipt-derived id by querying anchor count after the fact.
func (c *CastClient) Commit(ctx context.Context, treeSize uint64, root []byte, ts time.Time) (CommitReceipt, error) {
	if err := validateCommit(treeSize, root); err != nil {
		return CommitReceipt{}, err
	}
	unix := ts.Unix()
	if unix < 0 {
		return CommitReceipt{}, fmt.Errorf("anchor: timestamp before unix epoch (%d)", unix)
	}
	rootHex := "0x" + hex.EncodeToString(root)
	args := []string{
		"send",
		"--rpc-url", c.rpcURL,
		"--json",
		c.contract,
		"commit(uint64,bytes32,uint64)",
		strconv.FormatUint(treeSize, 10),
		rootHex,
		strconv.FormatUint(uint64(unix), 10),
	}
	// cast reads ETH_PRIVATE_KEY when --private-key is absent. Passing
	// it via env keeps the secret out of /proc/<pid>/cmdline.
	env := []string{"ETH_PRIVATE_KEY=" + c.privateKey}
	out, err := c.commandRunner(ctx, env, c.castBin, args...)
	if err != nil {
		return CommitReceipt{}, fmt.Errorf("cast send: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	receipt, err := parseCastSendOutput(out)
	if err != nil {
		return CommitReceipt{}, fmt.Errorf("cast send: parse receipt: %w", err)
	}
	return receipt, nil
}

func defaultCastRunner(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// Inherit the parent env so cast still sees PATH, HOME, etc., but
	// override / add the secret-bearing entries from `env` last so
	// they take precedence over anything inherited.
	cmd.Env = append(append([]string(nil), os.Environ()...), env...)
	return cmd.CombinedOutput()
}
