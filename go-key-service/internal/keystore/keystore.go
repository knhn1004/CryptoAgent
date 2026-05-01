// Package keystore stores agent ed25519 keypairs behind a pluggable
// interface. The HTTP API never returns private keys; only the service
// itself reads them when signing on behalf of an agent.
package keystore

import (
	"context"
	"crypto/ed25519"
	"errors"
)

var (
	ErrNotFound      = errors.New("keystore: agent not found")
	ErrAlreadyExists = errors.New("keystore: agent already exists")
)

type KeyStore interface {
	Create(ctx context.Context, agentID string) (ed25519.PublicKey, error)
	Get(ctx context.Context, agentID string) (ed25519.PublicKey, ed25519.PrivateKey, error)
	List(ctx context.Context) ([]string, error)
	Delete(ctx context.Context, agentID string) error
}
