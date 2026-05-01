package keystore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sort"
	"sync"
)

type memoryEntry struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

type Memory struct {
	mu   sync.RWMutex
	data map[string]memoryEntry
}

func NewMemory() *Memory {
	return &Memory{data: make(map[string]memoryEntry)}
}

func (m *Memory) Create(_ context.Context, agentID string) (ed25519.PublicKey, error) {
	if agentID == "" {
		return nil, ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[agentID]; ok {
		return nil, ErrAlreadyExists
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	m.data[agentID] = memoryEntry{pub: pub, priv: priv}
	return pub, nil
}

func (m *Memory) Get(_ context.Context, agentID string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.data[agentID]
	if !ok {
		return nil, nil, ErrNotFound
	}
	return e.pub, e.priv, nil
}

func (m *Memory) List(_ context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.data))
	for id := range m.data {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

func (m *Memory) Delete(_ context.Context, agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[agentID]; !ok {
		return ErrNotFound
	}
	delete(m.data, agentID)
	return nil
}
