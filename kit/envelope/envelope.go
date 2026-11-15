// Package envelope implements a generic authenticated message-framing
// protocol over a net.Conn: each frame carries a type string and a JSON
// payload, with an HMAC-SHA256 MAC that covers both — so a message cannot be
// replayed as a different type and a tampered payload is rejected before it
// is ever decoded.
//
// This package has no notion of what the messages mean; callers define their
// own type constants and payload structs and exchange them over a Conn.
package envelope

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"
)

// Envelope is the authenticated wire frame (one JSON object per line).
type Envelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
	MAC     string          `json:"mac"`
}

// ErrBadMAC is returned when a frame fails authentication.
var ErrBadMAC = errors.New("envelope: bad MAC")

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

// Decode unmarshals an already-authenticated payload.
func Decode(env Envelope, v any) error { return json.Unmarshal(env.Payload, v) }

// Conn is an authenticated-envelope connection. Send is safe for concurrent
// use; Recv must be called from a single goroutine.
type Conn struct {
	c   net.Conn
	key []byte
	dec *json.Decoder
	wmu sync.Mutex
	enc *json.Encoder
}

// NewConn wraps a net.Conn as an authenticated envelope channel.
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

// Recv reads and authenticates the next frame. The caller decodes the
// payload with Decode once it has switched on env.Type.
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

// Close closes the underlying connection.
func (c *Conn) Close() error { return c.c.Close() }
