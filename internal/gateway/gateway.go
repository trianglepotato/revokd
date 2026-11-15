// Package gateway is the data-plane enforcement point.
//
// It relays client TCP connections to a protected upstream, tracks every live
// connection (flow) per session, and counts the bytes each session moves. When
// an authenticated revoke arrives on the control channel it rejects new
// connections for that session AND closes the flows that are already open —
// token expiry alone does neither.
//
// This prototype enforces at the TCP-relay layer. On a WireGuard gateway the
// same Enforcer interface maps to: remove the peer (wgctrl), drop the peer's
// tunnel IP in nftables, and delete its conntrack entries.
package gateway

import (
	"bufio"
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/trianglepotato/revokd/internal/control"
	"github.com/trianglepotato/revokd/internal/policy"
	"github.com/trianglepotato/revokd/kit/envelope"
)

// Config configures a gateway.
type Config struct {
	ID          string
	Listen      string // data-plane listen address
	Upstream    string // protected resource
	Control     string // control-plane address
	Key         []byte // control-channel MAC key
	TokenKey    []byte // session-token key
	LeaseTTL    time.Duration
	ReportEvery time.Duration
	Logger      *log.Logger
}

type flow struct {
	client, upstream net.Conn
	once             sync.Once
}

func (f *flow) close() {
	f.once.Do(func() {
		_ = f.client.Close()
		_ = f.upstream.Close()
	})
}

// Gateway is one data-plane node. Several gateways run Active-Active behind
// the same control plane.
type Gateway struct {
	cfg   Config
	store *policy.Store
	ln    net.Listener
	ctrl  *envelope.Conn

	mu       sync.Mutex
	flows    map[string]map[*flow]struct{}
	counters map[string]*atomic.Int64

	lastHB atomic.Int64 // unix nanos of last authenticated heartbeat
}

// New creates a gateway.
func New(cfg Config) *Gateway {
	if cfg.LeaseTTL == 0 {
		cfg.LeaseTTL = time.Second
	}
	if cfg.ReportEvery == 0 {
		cfg.ReportEvery = 50 * time.Millisecond
	}
	if cfg.Logger == nil {
		cfg.Logger = log.New(io.Discard, "", 0)
	}
	return &Gateway{
		cfg:      cfg,
		store:    policy.NewStore(),
		flows:    map[string]map[*flow]struct{}{},
		counters: map[string]*atomic.Int64{},
	}
}

// Start opens the data-plane listener and the control channel.
func (g *Gateway) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", g.cfg.Listen)
	if err != nil {
		return err
	}
	g.ln = ln
	c, err := net.DialTimeout("tcp", g.cfg.Control, 2*time.Second)
	if err != nil {
		_ = ln.Close()
		return fmt.Errorf("dial control: %w", err)
	}
	g.ctrl = envelope.NewConn(c, g.cfg.Key)
	if err := g.ctrl.Send(control.TypeHello, control.Hello{GatewayID: g.cfg.ID}); err != nil {
		return err
	}
	go g.controlLoop()
	go g.reportLoop(ctx)
	go g.acceptLoop()
	go func() { <-ctx.Done(); g.Close() }()
	return nil
}

// Addr is the data-plane address.
func (g *Gateway) Addr() string { return g.ln.Addr().String() }

// Close stops the gateway and drops every flow.
func (g *Gateway) Close() {
	if g.ln != nil {
		_ = g.ln.Close()
	}
	if g.ctrl != nil {
		_ = g.ctrl.Close()
	}
	g.mu.Lock()
	all := g.flows
	g.flows = map[string]map[*flow]struct{}{}
	g.mu.Unlock()
	for _, fs := range all {
		for f := range fs {
			f.close()
		}
	}
}

// Store exposes the local policy view (read-only use).
func (g *Gateway) Store() *policy.Store { return g.store }

func (g *Gateway) leaseValid() bool {
	last := g.lastHB.Load()
	return last != 0 && time.Since(time.Unix(0, last)) <= g.cfg.LeaseTTL
}

func (g *Gateway) acceptLoop() {
	for {
		c, err := g.ln.Accept()
		if err != nil {
			return
		}
		go g.handle(c)
	}
}

func deny(c net.Conn, reason string) {
	_, _ = c.Write([]byte("DENY " + reason + "\n"))
	_ = c.Close()
}

// handle runs one client connection. Handshake: "HELLO <session> <token>\n".
func (g *Gateway) handle(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(c)
	line, err := r.ReadString('\n')
	if err != nil {
		_ = c.Close()
		return
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || parts[0] != "HELLO" {
		deny(c, "bad-hello")
		return
	}
	sid, token := parts[1], parts[2]
	if !hmac.Equal([]byte(token), []byte(control.SessionToken(g.cfg.TokenKey, sid))) {
		deny(c, "bad-token")
		return
	}
	// Fail closed: a gateway that has lost its control lease cannot learn
	// about revocations, so it stops admitting new connections.
	if !g.leaseValid() {
		deny(c, "control-lease-expired")
		return
	}
	if g.store.Revoked(sid) {
		deny(c, "revoked")
		return
	}
	up, err := net.DialTimeout("tcp", g.cfg.Upstream, 2*time.Second)
	if err != nil {
		deny(c, "upstream-unavailable")
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	f := &flow{client: c, upstream: up}
	g.addFlow(sid, f)
	// Close the race between the Revoked check and addFlow: a revoke applied
	// in between would have missed this flow.
	if g.store.Revoked(sid) {
		g.removeFlow(sid, f)
		f.close()
		return
	}
	if _, err := c.Write([]byte("OK\n")); err != nil {
		g.removeFlow(sid, f)
		f.close()
		return
	}

	ctr := g.counter(sid)
	done := make(chan struct{}, 2)
	go func() { countingCopy(up, r, ctr); done <- struct{}{} }()
	go func() { countingCopy(c, up, ctr); done <- struct{}{} }()
	<-done
	f.close()
	<-done
	g.removeFlow(sid, f)
}

// countingCopy forwards src to dst and adds the bytes to ctr before writing,
// so the counter reflects what the gateway attempted to forward.
func countingCopy(dst io.Writer, src io.Reader, ctr *atomic.Int64) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			ctr.Add(int64(n))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (g *Gateway) addFlow(sid string, f *flow) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.flows[sid] == nil {
		g.flows[sid] = map[*flow]struct{}{}
	}
	g.flows[sid][f] = struct{}{}
}

func (g *Gateway) removeFlow(sid string, f *flow) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.flows[sid], f)
	if len(g.flows[sid]) == 0 {
		delete(g.flows, sid)
	}
}

func (g *Gateway) counter(sid string) *atomic.Int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	c := g.counters[sid]
	if c == nil {
		c = &atomic.Int64{}
		g.counters[sid] = c
	}
	return c
}

// killSession closes every open flow of a session and returns how many.
func (g *Gateway) killSession(sid string) int {
	g.mu.Lock()
	fs := g.flows[sid]
	delete(g.flows, sid)
	g.mu.Unlock()
	for f := range fs {
		f.close()
	}
	return len(fs)
}

// ActiveFlows returns the number of open flows for a session.
func (g *Gateway) ActiveFlows(sid string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.flows[sid])
}

func (g *Gateway) controlLoop() {
	for {
		env, err := g.ctrl.Recv()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				g.cfg.Logger.Printf("gateway %s: control channel lost: %v", g.cfg.ID, err)
			}
			g.lastHB.Store(0) // lose the lease immediately: fail closed
			return
		}
		switch env.Type {
		case control.TypeHeartbeat:
			g.lastHB.Store(time.Now().UnixNano())
		case control.TypeEvent:
			var ev control.Event
			if err := envelope.Decode(env, &ev); err != nil {
				continue
			}
			now := time.Now()
			st := g.store.Apply(ev, now)
			closed := 0
			// Enforce on the data path before acknowledging.
			if st == policy.Applied && ev.Action == control.ActionRevoke {
				closed = g.killSession(ev.SessionID)
			}
			_ = g.ctrl.Send(control.TypeAck, control.Ack{
				EventID: ev.ID, GatewayID: g.cfg.ID, SessionID: ev.SessionID,
				Status: string(st), FlowsClosed: closed, AppliedAt: time.Now(),
			})
		}
	}
}

func (g *Gateway) reportLoop(ctx context.Context) {
	t := time.NewTicker(g.cfg.ReportEvery)
	defer t.Stop()
	last := map[string]int64{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		g.mu.Lock()
		snap := make(map[string]int64, len(g.counters))
		for sid, c := range g.counters {
			if v := c.Load(); v != last[sid] {
				snap[sid] = v
				last[sid] = v
			}
		}
		g.mu.Unlock()
		if len(snap) == 0 {
			continue
		}
		_ = g.ctrl.Send(control.TypeUsage, control.Usage{GatewayID: g.cfg.ID, At: time.Now(), Sessions: snap})
	}
}
