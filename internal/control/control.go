// Package control implements the authenticated control channel (sideband)
// between the control plane and VPN gateways.
//
// The data path (tunnel traffic) and the control path are separate TCP
// connections. Every control message is wrapped in an Envelope whose MAC
// covers the message type and payload, so a gateway never acts on a revoke
// (or heartbeat) it cannot authenticate.
package control

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sync"
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

// Envelope is the authenticated wire frame (one JSON object per line).
type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

// ErrBadMAC is returned when a frame fails authentication.
var ErrBadMAC = errors.New("control: bad MAC")

func sign(key []byte, typ string, payload []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(typ))
	h.Write([]byte{0})
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// Seal builds an authenticated envelope.
func Seal(key []byte, typ string, v any) (Envelope, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Type: typ, Payload: b, MAC: sign(key, typ, b)}, nil
}

// Open verifies an envelope and decodes its payload into v.
func Open(key []byte, env Envelope, v any) error {
	want := sign(key, env.Type, env.Payload)
	if !hmac.Equal([]byte(want), []byte(env.MAC)) {
		return ErrBadMAC
	}
	if v == nil {
		return nil
	}
	return json.Unmarshal(env.Payload, v)
}

// Conn is a control-channel connection. Send is safe for concurrent use;
// Recv must be called from a single goroutine.
type Conn struct {
	c   net.Conn
	key []byte
	dec *json.Decoder
	wmu sync.Mutex
	enc *json.Encoder
}

// NewConn wraps a net.Conn as an authenticated control channel.
func NewConn(c net.Conn, key []byte) *Conn {
	return &Conn{c: c, key: key, dec: json.NewDecoder(bufio.NewReader(c)), enc: json.NewEncoder(c)}
}

// Send seals and writes one message.
func (c *Conn) Send(typ string, v any) error {
	env, err := Seal(c.key, typ, v)
	if err != nil {
		return err
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	return c.enc.Encode(env)
}

// Recv reads and authenticates the next frame. The caller decodes the payload
// with Decode once it has switched on env.Type.
func (c *Conn) Recv() (Envelope, error) {
	var env Envelope
	if err := c.dec.Decode(&env); err != nil {
		return Envelope{}, err
	}
	if err := Open(c.key, env, nil); err != nil {
		return Envelope{}, err
	}
	return env, nil
}

// Decode unmarshals an already-authenticated payload.
func Decode(env Envelope, v any) error { return json.Unmarshal(env.Payload, v) }

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.c.Close() }

// SessionToken derives the credential a client presents to a gateway for a
// session. In production this would be a short-lived token from the IdP; here
// it is an HMAC so gateways can verify it without a round trip.
func SessionToken(key []byte, sessionID string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("session:" + sessionID))
	return hex.EncodeToString(h.Sum(nil))
}

// NewID returns a random 128-bit identifier.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
