// merkle-verify rebuilds an append-only Merkle tree from a leaves file
// and checks a historical (root, size) snapshot for consistency. Exits 0
// on a passing report, 1 on divergence with a diagnostic on stderr.
//
// Leaves file format: newline-delimited hex of LEAF DATA (not leaf hash).
// The CLI applies HashLeaf internally so file content matches what an
// auditor would normally have on hand.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/merkle"
)

func main() {
	historicalRoot := flag.String("historical-root", "", "hex-encoded historical root (required)")
	historicalSize := flag.Uint64("historical-size", 0, "size of historical snapshot (required)")
	leavesFile := flag.String("leaves-file", "", "newline-delimited hex of leaf payloads (required)")
	flag.Parse()

	if *historicalRoot == "" || *leavesFile == "" {
		fmt.Fprintln(os.Stderr, "usage: merkle-verify --historical-root HEX --historical-size N --leaves-file PATH")
		os.Exit(2)
	}

	rootBytes, err := hex.DecodeString(*historicalRoot)
	if err != nil || len(rootBytes) != merkle.HashSize {
		fmt.Fprintf(os.Stderr, "invalid --historical-root: must be %d-byte hex\n", merkle.HashSize)
		os.Exit(2)
	}

	tree, err := buildTreeFromFile(*leavesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "leaves: %v\n", err)
		os.Exit(2)
	}

	v := merkle.NewVerifier(tree)
	report, verr := v.VerifyHistoricalRoot(rootBytes, *historicalSize)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)

	if verr != nil {
		fmt.Fprintf(os.Stderr, "DIVERGENCE: %s\n", report.Message)
		os.Exit(1)
	}
}

func buildTreeFromFile(path string) (*merkle.Tree, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tree := merkle.New()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		data, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		tree.Append(data)
	}
	return tree, sc.Err()
}
