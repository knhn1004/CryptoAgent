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

// Service issues, verifies, and revokes capability tokens. The service
// owns its own Ed25519 signing key (in-memory; rotated on restart) and
// consults the keystore to confirm agents exist at issuance time.
type Service struct {
	store      keystore.KeyStore
	revocation RevocationStore
	signPriv   ed25519.PrivateKey
	signPub    ed25519.PublicKey
	clock      Clock
	logger     *slog.Logger
}

// Options configures a Service. Zero values get sensible defaults.
type Options struct {
	Revocation RevocationStore
	Clock      Clock
	Logger     *slog.Logger
	// SigningKey lets callers inject a key (e.g. for tests). If nil, a
	// fresh keypair is generated.
	SigningPrivateKey ed25519.PrivateKey
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
		store:      store,
		revocation: rev,
		signPriv:   priv,
		signPub:    pub,
		clock:      clock,
		logger:     logger,
	}, nil
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
// capability.Err* sentinels.
func (s *Service) Verify(_ context.Context, req VerifyRequest) (*Token, error) {
	var tok Token
	if err := json.Unmarshal(req.ClaimsJSON, &tok); err != nil {
		return nil, ErrMalformedToken
	}
	canonical, err := tok.Canonical()
	if err != nil {
		return nil, ErrMalformedToken
	}
	if !ed25519.Verify(s.signPub, canonical, req.Signature) {
		return nil, ErrInvalidSignature
	}
	if s.clock().Unix() >= tok.ExpiresAt {
		return nil, ErrExpired
	}
	if s.revocation.IsRevoked(tok.TokenID) {
		return nil, ErrRevoked
	}
	if tok.AgentID != req.AgentID {
		return nil, ErrAgentMismatch
	}
	actionOK, targetOK := tok.Allows(req.ActionType, req.Target)
	if !actionOK {
		return nil, ErrActionTypeNotAllowed
	}
	if !targetOK {
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
