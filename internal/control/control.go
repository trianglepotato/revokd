// Package control defines the messages exchanged on the control channel
// (sideband) between the control plane and VPN gateways, and the
// session-token derivation clients use to authenticate to a gateway.
//
// The data path (tunnel traffic) and the control path are separate TCP
// connections. Messages travel inside kit/envelope frames, whose MAC covers
// the message type and payload, so a gateway never acts on a revoke (or
// heartbeat) it cannot authenticate.
package control

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Message types carried on the control channel.
const (
	TypeHello     = "hello"     // gateway -> plane: register
	TypeEvent     = "event"     // plane -> gateway: policy change (revoke/restore)
	TypeAck       = "ack"       // gateway -> plane: event applied
	TypeUsage     = "usage"     // gateway -> plane: per-session byte counters
	TypeHeartbeat = "heartbeat" // plane -> gateway: lease renewal
)

// Action is the policy change an Event requests.
type Action string

const (
	ActionRevoke  Action = "revoke"
	ActionRestore Action = "restore"
)

// Event is a session-scoped policy change, modelled after the CAEP
// "session-revoked" event: it names the subject (session/user/device), carries a
// unique ID for idempotency and a per-session monotonic Epoch so that an old
// event delivered late can never override a newer decision.
type Event struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id,omitempty"`
	DeviceID  string    `json:"device_id,omitempty"`
	Epoch     uint64    `json:"epoch"`
	Action    Action    `json:"action"`
	Reason    string    `json:"reason"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Hello registers a gateway on the control channel.
type Hello struct {
	GatewayID string `json:"gateway_id"`
}

// Ack reports how a gateway handled an Event.
type Ack struct {
	EventID     string    `json:"event_id"`
	GatewayID   string    `json:"gateway_id"`
	SessionID   string    `json:"session_id"`
	Status      string    `json:"status"` // applied | duplicate | stale | expired
	FlowsClosed int       `json:"flows_closed"`
	AppliedAt   time.Time `json:"applied_at"`
}

// Usage reports cumulative bytes forwarded per session on one gateway.
type Usage struct {
	GatewayID string           `json:"gateway_id"`
	At        time.Time        `json:"at"`
	Sessions  map[string]int64 `json:"sessions"`
}

// Heartbeat renews the gateway's control lease.
type Heartbeat struct {
	At time.Time `json:"at"`
}

// SessionToken derives the credential a client presents to a gateway for a
// session. In production this would be a short-lived token from the IdP; here
// it is an HMAC so gateways can verify it without a round trip.
func SessionToken(key []byte, sessionID string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("session:" + sessionID))
	return hex.EncodeToString(h.Sum(nil))
}
