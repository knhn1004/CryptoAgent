package capability

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
)

// Clock returns the current time. Injectable so tests can pin it.
type Clock func() time.Time

// RejectionSink is invoked on every Verify denial so an external
// observer (the audit-log dashboard feed) can record token-policy
// failures alongside Merkle append failures. It runs synchronously on
// the verify path; impls must not block.
type RejectionSink func(agentID, actionType, target, reason string)

// Service issues, verifies, and revokes capability tokens. The service
// owns its own Ed25519 signing key (in-memory; rotated on restart) and
// consults the keystore to confirm agents exist at issuance time.
type Service struct {
	store         keystore.KeyStore
	revocation    RevocationStore
	signPriv      ed25519.PrivateKey
	signPub       ed25519.PublicKey
	clock         Clock
	logger        *slog.Logger
	rejectionSink RejectionSink
}

// Options configures a Service. Zero values get sensible defaults.
type Options struct {
	Revocation RevocationStore
	Clock      Clock
	Logger     *slog.Logger
	// SigningKey lets callers inject a key (e.g. for tests). If nil, a
	// fresh keypair is generated.
	SigningPrivateKey ed25519.PrivateKey
	// RejectionSink, if set, is called on every Verify denial.
	RejectionSink RejectionSink
}

// NewService constructs a Service. The keystore is required; everything
// else has a sensible default.
func NewService(store keystore.KeyStore, opts Options) (*Service, error) {
	if store == nil {
		return nil, errors.New("capability: keystore is required")
	}
	rev := opts.Revocation
	if rev == nil {
		rev = NewMemoryStore()
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	priv := opts.SigningPrivateKey
	var pub ed25519.PublicKey
	if priv == nil {
		var err error
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	} else {
		if len(priv) != ed25519.PrivateKeySize {
			return nil, errors.New("capability: signing key must be ed25519.PrivateKeySize")
		}
		pub = priv.Public().(ed25519.PublicKey)
	}
	return &Service{
		store:         store,
		revocation:    rev,
		signPriv:      priv,
		signPub:       pub,
		clock:         clock,
		logger:        logger,
		rejectionSink: opts.RejectionSink,
	}, nil
}

// SetRejectionSink installs a sink after construction. Useful when the
// capability service and the audit pipeline are wired in different
// orders during startup.
func (s *Service) SetRejectionSink(sink RejectionSink) {
	s.rejectionSink = sink
}

func (s *Service) emitRejection(req VerifyRequest, reason string) {
	if s.rejectionSink == nil {
		return
	}
	s.rejectionSink(req.AgentID, req.ActionType, req.Target, reason)
}

// IssueRequest is the input to Service.Issue.
type IssueRequest struct {
	AgentID     string
	ActionTypes []string
	Targets     []string
	TTLSeconds  int64
}

// Issue mints a fresh token for the agent. It returns the token, the
// canonical claim bytes (exactly what was signed) and the detached
// signature. Returns ErrUnknownAgent if the agent is not in the
// keystore, ErrInvalidTTL if ttl_seconds <= 0.
func (s *Service) Issue(ctx context.Context, req IssueRequest) (*Token, []byte, []byte, error) {
	if req.TTLSeconds <= 0 {
		return nil, nil, nil, ErrInvalidTTL
	}
	if _, _, err := s.store.Get(ctx, req.AgentID); err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, nil, nil, ErrUnknownAgent
		}
		return nil, nil, nil, err
	}
	now := s.clock().Unix()
	tok := &Token{
		TokenID:     uuid.NewString(),
		AgentID:     req.AgentID,
		ActionTypes: append([]string(nil), req.ActionTypes...),
		Targets:     append([]string(nil), req.Targets...),
		IssuedAt:    now,
		ExpiresAt:   now + req.TTLSeconds,
	}
	canonical, err := tok.Canonical()
	if err != nil {
		return nil, nil, nil, err
	}
	sig := ed25519.Sign(s.signPriv, canonical)
	s.logger.Info("token issued",
		"token_id", tok.TokenID,
		"agent_id", tok.AgentID,
		"expires_at", tok.ExpiresAt,
	)
	return tok, canonical, sig, nil
}

// VerifyRequest is the input to Service.Verify.
type VerifyRequest struct {
	ClaimsJSON []byte
	Signature  []byte
	AgentID    string
	ActionType string
	Target     string
}

// Verify returns the parsed token on success, or one of the
// capability.Err* sentinels. Every denial path also calls the
// configured RejectionSink (if any) so the dashboard feed surfaces
// token policy failures alongside Merkle pipeline rejections.
func (s *Service) Verify(_ context.Context, req VerifyRequest) (*Token, error) {
	var tok Token
	if err := json.Unmarshal(req.ClaimsJSON, &tok); err != nil {
		s.emitRejection(req, "malformed_token")
		return nil, ErrMalformedToken
	}
	canonical, err := tok.Canonical()
	if err != nil {
		s.emitRejection(req, "malformed_token")
		return nil, ErrMalformedToken
	}
	if !ed25519.Verify(s.signPub, canonical, req.Signature) {
		s.emitRejection(req, "invalid_signature")
		return nil, ErrInvalidSignature
	}
	if s.clock().Unix() >= tok.ExpiresAt {
		s.emitRejection(req, "expired")
		return nil, ErrExpired
	}
	if s.revocation.IsRevoked(tok.TokenID) {
		s.emitRejection(req, "revoked")
		return nil, ErrRevoked
	}
	if tok.AgentID != req.AgentID {
		s.emitRejection(req, "agent_mismatch")
		return nil, ErrAgentMismatch
	}
	actionOK, targetOK := tok.Allows(req.ActionType, req.Target)
	if !actionOK {
		s.emitRejection(req, "action_type_not_allowed")
		return nil, ErrActionTypeNotAllowed
	}
	if !targetOK {
		s.emitRejection(req, "target_not_allowed")
		return nil, ErrTargetNotAllowed
	}
	return &tok, nil
}

// Revoke records tokenID in the revocation set. Idempotent.
func (s *Service) Revoke(_ context.Context, tokenID string) {
	s.revocation.Revoke(tokenID)
	s.logger.Info("token revoked", "token_id", tokenID)
}

// SigningPublicKey returns the service's Ed25519 public key for
// out-of-band signature inspection.
func (s *Service) SigningPublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.signPub...)
}
