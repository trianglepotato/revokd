// Package policy holds the gateway-local view of session policy.
//
// Events can arrive more than once (control-plane retries, reconnects) and out
// of order (two control-plane replicas, network reordering). The store makes
// applying an event idempotent (by event ID) and order-safe (by a per-session
// monotonic epoch): a late "restore" with an older epoch can never undo a newer
// "revoke".
package policy

import (
	"sync"
	"time"

	"github.com/trianglepotato/revokd/internal/control"
)

// Status is the outcome of applying an event.
type Status string

const (
	Applied   Status = "applied"
	Duplicate Status = "duplicate"
	Stale     Status = "stale"
	Expired   Status = "expired"
)

type entry struct {
	epoch   uint64
	revoked bool
}

// Store is safe for concurrent use.
type Store struct {
	mu       sync.RWMutex
	seen     map[string]struct{}
	sessions map[string]*entry
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{seen: map[string]struct{}{}, sessions: map[string]*entry{}}
}

// Apply applies ev and reports what happened.
func (s *Store) Apply(ev control.Event, now time.Time) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[ev.ID]; ok {
		return Duplicate
	}
	s.seen[ev.ID] = struct{}{}
	if !ev.ExpiresAt.IsZero() && now.After(ev.ExpiresAt) {
		return Expired
	}
	e := s.sessions[ev.SessionID]
	if e == nil {
		e = &entry{}
		s.sessions[ev.SessionID] = e
	}
	if ev.Epoch <= e.epoch {
		return Stale
	}
	e.epoch = ev.Epoch
	e.revoked = ev.Action == control.ActionRevoke
	return Applied
}

// Revoked reports whether a session is currently revoked.
func (s *Store) Revoked(sessionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := s.sessions[sessionID]
	return e != nil && e.revoked
}

// Epoch returns the current policy epoch for a session.
func (s *Store) Epoch(sessionID string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e := s.sessions[sessionID]; e != nil {
		return e.epoch
	}
	return 0
}
