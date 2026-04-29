// Package keys handles Ed25519 keypair generation, storage, and lookup
// for registered agents.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
)

var (
	ErrAgentExists   = errors.New("keys: agent already registered")
	ErrAgentNotFound = errors.New("keys: agent not found")
	ErrEmptyAgentID  = errors.New("keys: agent_id must not be empty")
)

// Store persists agent keypairs. Implementations must be safe for concurrent use.
type Store interface {
	// Create generates a fresh Ed25519 keypair for agentID and stores it.
	// Returns ErrAgentExists if agentID is already registered.
	Create(agentID string) (ed25519.PublicKey, error)
	// PublicKey returns the public key for agentID, or ErrAgentNotFound.
	PublicKey(agentID string) (ed25519.PublicKey, error)
}

// MemoryStore is an in-memory Store. Private keys never leave the process.
// Phase-1 only: production deployments need a KMS/HSM-backed store.
type MemoryStore struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PrivateKey
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{keys: make(map[string]ed25519.PrivateKey)}
}

func (s *MemoryStore) Create(agentID string) (ed25519.PublicKey, error) {
	if agentID == "" {
		return nil, ErrEmptyAgentID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[agentID]; ok {
		return nil, ErrAgentExists
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	s.keys[agentID] = priv
	return pub, nil
}

func (s *MemoryStore) PublicKey(agentID string) (ed25519.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	priv, ok := s.keys[agentID]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return priv.Public().(ed25519.PublicKey), nil
}
