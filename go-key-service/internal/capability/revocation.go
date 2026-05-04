package capability

import "sync"

// RevocationStore tracks the set of revoked token ids.
type RevocationStore interface {
	Revoke(tokenID string)
	IsRevoked(tokenID string) bool
}

// MemoryStore is an in-memory RevocationStore safe for concurrent use.
type MemoryStore struct {
	mu  sync.RWMutex
	ids map[string]struct{}
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{ids: make(map[string]struct{})}
}

func (m *MemoryStore) Revoke(tokenID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ids[tokenID] = struct{}{}
}

func (m *MemoryStore) IsRevoked(tokenID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.ids[tokenID]
	return ok
}
