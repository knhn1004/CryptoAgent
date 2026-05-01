package merkle

import (
	"encoding/hex"
	"fmt"
)

// VerificationReport is the output of a root-consistency check, suitable
// for both CLI/HTTP exposure and structured logging.
type VerificationReport struct {
	OK             bool   `json:"ok"`
	Message        string `json:"message"`
	HistoricalRoot string `json:"historical_root"`
	HistoricalSize uint64 `json:"historical_size"`
	LiveRoot       string `json:"live_root"`
	LiveSize       uint64 `json:"live_size"`
}

// Verifier checks historical roots against the live tree.
type Verifier struct{ tree *Tree }

func NewVerifier(t *Tree) *Verifier { return &Verifier{tree: t} }

// VerifyHistoricalRoot returns OK iff the live tree's first
// `historicalSize` leaves still hash to `historicalRoot`. The check is
// equivalent to RFC 6962 consistency between the historical snapshot and
// the live tree.
func (v *Verifier) VerifyHistoricalRoot(historicalRoot []byte, historicalSize uint64) (*VerificationReport, error) {
	liveSize := v.tree.Size()
	liveRoot := v.tree.Root()

	report := &VerificationReport{
		HistoricalRoot: hex.EncodeToString(historicalRoot),
		HistoricalSize: historicalSize,
		LiveRoot:       hex.EncodeToString(liveRoot),
		LiveSize:       liveSize,
	}

	if historicalSize > liveSize {
		report.Message = fmt.Sprintf("size regression: historical=%d live=%d", historicalSize, liveSize)
		return report, ErrSizeRegression
	}

	proof, err := v.tree.ProofForRange(historicalSize, liveSize)
	if err != nil {
		report.Message = err.Error()
		return report, err
	}

	if err := VerifyConsistency(historicalRoot, liveRoot, historicalSize, liveSize, proof); err != nil {
		report.Message = err.Error()
		return report, err
	}

	report.OK = true
	report.Message = "consistent"
	return report, nil
}
