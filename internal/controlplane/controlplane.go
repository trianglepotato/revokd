// Package controlplane aggregates usage from all gateways, detects bulk
// exfiltration, and pushes signed revoke events to every gateway over the
// control channel, collecting an ACK from each before a revocation counts as
// enforced.
package controlplane

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/trianglepotato/revokd/internal/control"
	"github.com/trianglepotato/revokd/kit/envelope"
	"github.com/trianglepotato/revokd/kit/idgen"
)

// Config configures the control plane.
type Config struct {
	Listen         string
	Key            []byte
	Window         time.Duration // detection window
	ThresholdBytes int64         // bytes per session within Window that trigger revoke
	HeartbeatEvery time.Duration
	EventTTL       time.Duration
	Audit          io.Writer // JSON-lines audit log; nil disables
	Logger         *log.Logger
}

type sample struct {
	at    time.Time
	total int64
}

// Record is the audit record of one revocation.
type Record struct {
	EventID    string                 `json:"event_id"`
	SessionID  string                 `json:"session_id"`
	Reason     string                 `json:"reason"`
	Epoch      uint64                 `json:"epoch"`
	DetectedAt time.Time              `json:"detected_at"`
	IssuedAt   time.Time              `json:"issued_at"`
	Expected   int                    `json:"expected_acks"`
	Acks       map[string]control.Ack `json:"acks"`
	AllAckedAt time.Time              `json:"all_acked_at"`
}

// Plane is the control plane.
type Plane struct {
	cfg Config
	ln  net.Listener

	mu      sync.Mutex
	gws     map[string]*envelope.Conn
	latest  map[string]map[string]int64 // session -> gateway -> cumulative bytes
	samples map[string][]sample         // session -> totals over time
	epochs  map[string]uint64
	revoked map[string]bool
	pending map[string]*Record

	records chan Record
}

// New creates a control plane.
func New(cfg Config) *Plane {
	if cfg.HeartbeatEvery == 0 {
		cfg.HeartbeatEvery = 200 * time.Millisecond
	}
	if cfg.EventTTL == 0 {
		cfg.EventTTL = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	return &Plane{
		cfg:     cfg,
		gws:     map[string]*envelope.Conn{},
		latest:  map[string]map[string]int64{},
		samples: map[string][]sample{},
		epochs:  map[string]uint64{},
		revoked: map[string]bool{},
		pending: map[string]*Record{},
		records: make(chan Record, 256),
	}
}

// Start begins accepting gateway control connections.
func (p *Plane) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		return err
	}
	p.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serveGateway(c)
		}
	}()
	go p.heartbeatLoop(ctx)
	go func() { <-ctx.Done(); p.Close() }()
	return nil
}

// Addr is the control-channel address.
func (p *Plane) Addr() string { return p.ln.Addr().String() }

// Close stops the control plane and drops every gateway connection.
func (p *Plane) Close() {
	_ = p.ln.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.gws {
		_ = c.Close()
	}
}

// Records delivers a Record once every gateway has acknowledged a revoke.
func (p *Plane) Records() <-chan Record { return p.records }

// WaitGateways blocks until n gateways are registered.
func (p *Plane) WaitGateways(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		got := len(p.gws)
		p.mu.Unlock()
		if got >= n {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func (p *Plane) serveGateway(c net.Conn) {
	cc := envelope.NewConn(c, p.cfg.Key)
	env, err := cc.Recv()
	if err != nil || env.Type != control.TypeHello {
		_ = c.Close()
		return
	}
	var h control.Hello
	if envelope.Decode(env, &h) != nil || h.GatewayID == "" {
		_ = c.Close()
		return
	}
	p.mu.Lock()
	p.gws[h.GatewayID] = cc
	p.mu.Unlock()
	_ = cc.Send(control.TypeHeartbeat, control.Heartbeat{At: time.Now()})

	defer func() {
		p.mu.Lock()
		if p.gws[h.GatewayID] == cc {
			delete(p.gws, h.GatewayID)
		}
		p.mu.Unlock()
		_ = c.Close()
	}()
	for {
		env, err := cc.Recv()
		if err != nil {
			return
		}
		switch env.Type {
		case control.TypeUsage:
			var u control.Usage
			if envelope.Decode(env, &u) == nil {
				p.onUsage(u)
			}
		case control.TypeAck:
			var a control.Ack
			if envelope.Decode(env, &a) == nil {
				p.onAck(a)
			}
		}
	}
}

// onUsage folds one gateway report into the per-session sliding window and
// revokes when the session moved more than ThresholdBytes within Window.
// Totals are summed across gateways so a session cannot evade detection by
// spreading traffic over Active-Active nodes.
func (p *Plane) onUsage(u control.Usage) {
	now := time.Now()
	var toRevoke []string
	p.mu.Lock()
	for sid, cum := range u.Sessions {
		per := p.latest[sid]
		if per == nil {
			per = map[string]int64{}
			p.latest[sid] = per
		}
		per[u.GatewayID] = cum
		var total int64
		for _, v := range per {
			total += v
		}
		s := p.samples[sid]
		if len(s) == 0 {
			// New session: everything it has moved so far is inside the window.
			s = append(s, sample{now, 0})
		}
		s = append(s, sample{now, total})
		// Keep the newest sample older than the window as the baseline.
		cut := 0
		for i := range s {
			if now.Sub(s[i].at) <= p.cfg.Window {
				break
			}
			cut = i
		}
		s = s[cut:]
		p.samples[sid] = s
		base := s[0].total
		if total-base >= p.cfg.ThresholdBytes && !p.revoked[sid] {
			toRevoke = append(toRevoke, sid)
		}
	}
	p.mu.Unlock()
	for _, sid := range toRevoke {
		p.revoke(sid, "bulk-transfer-threshold", now)
	}
}

// Revoke revokes a session manually (e.g. from a SOC console or an IdP signal).
func (p *Plane) Revoke(sessionID, reason string) string {
	return p.revoke(sessionID, reason, time.Now())
}

func (p *Plane) revoke(sid, reason string, detectedAt time.Time) string {
	p.mu.Lock()
	if p.revoked[sid] && reason == "bulk-transfer-threshold" {
		p.mu.Unlock()
		return ""
	}
	p.revoked[sid] = true
	p.epochs[sid]++
	now := time.Now()
	ev := control.Event{
		ID: idgen.New(), SessionID: sid, Epoch: p.epochs[sid],
		Action: control.ActionRevoke, Reason: reason,
		IssuedAt: now, ExpiresAt: now.Add(p.cfg.EventTTL),
	}
	rec := &Record{
		EventID: ev.ID, SessionID: sid, Reason: reason, Epoch: ev.Epoch,
		DetectedAt: detectedAt, IssuedAt: now, Expected: len(p.gws),
		Acks: map[string]control.Ack{},
	}
	p.pending[ev.ID] = rec
	targets := make([]*envelope.Conn, 0, len(p.gws))
	for _, c := range p.gws {
		targets = append(targets, c)
	}
	p.mu.Unlock()

	for _, c := range targets {
		if err := c.Send(control.TypeEvent, ev); err != nil {
			p.cfg.Logger.Printf("send revoke %s: %v", ev.ID, err)
		}
	}
	return ev.ID
}

// Resend re-delivers an event (used to exercise idempotency).
func (p *Plane) Resend(ev control.Event) {
	p.mu.Lock()
	targets := make([]*envelope.Conn, 0, len(p.gws))
	for _, c := range p.gws {
		targets = append(targets, c)
	}
	p.mu.Unlock()
	for _, c := range targets {
		_ = c.Send(control.TypeEvent, ev)
	}
}

func (p *Plane) onAck(a control.Ack) {
	p.mu.Lock()
	rec := p.pending[a.EventID]
	if rec == nil {
		p.mu.Unlock()
		return
	}
	rec.Acks[a.GatewayID] = a
	if len(rec.Acks) < rec.Expected {
		p.mu.Unlock()
		return
	}
	rec.AllAckedAt = time.Now()
	delete(p.pending, a.EventID)
	out := *rec
	p.mu.Unlock()

	if p.cfg.Audit != nil {
		b, _ := json.Marshal(out)
		_, _ = p.cfg.Audit.Write(append(b, '\n'))
	}
	select {
	case p.records <- out:
	default:
	}
}

// Pending returns event IDs still waiting for ACKs, oldest first. A gateway
// listed here has not confirmed enforcement and should be retried or drained.
func (p *Plane) Pending() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	type kv struct {
		id string
		t  time.Time
	}
	var xs []kv
	for id, r := range p.pending {
		xs = append(xs, kv{id, r.IssuedAt})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].t.Before(xs[j].t) })
	ids := make([]string, len(xs))
	for i, x := range xs {
		ids[i] = x.id
	}
	return ids
}

func (p *Plane) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(p.cfg.HeartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p.mu.Lock()
		targets := make([]*envelope.Conn, 0, len(p.gws))
		for _, c := range p.gws {
			targets = append(targets, c)
		}
		p.mu.Unlock()
		for _, c := range targets {
			_ = c.Send(control.TypeHeartbeat, control.Heartbeat{At: time.Now()})
		}
	}
}
