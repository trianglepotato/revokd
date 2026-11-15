// Package e2e runs the control plane, two Active-Active gateways and a
// protected upstream over real TCP sockets.
package e2e

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/trianglepotato/revokd/internal/client"
	"github.com/trianglepotato/revokd/internal/control"
	"github.com/trianglepotato/revokd/internal/controlplane"
	"github.com/trianglepotato/revokd/internal/gateway"
	"github.com/trianglepotato/revokd/internal/upstream"
)

var (
	ctlKey   = []byte("control-key")
	tokenKey = []byte("token-key")
)

type env struct {
	plane  *controlplane.Plane
	gwA    *gateway.Gateway
	gwB    *gateway.Gateway
	cancel context.CancelFunc
}

func setup(t *testing.T, threshold int64) *env {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	up, err := upstream.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(up.Close)
	p := controlplane.New(controlplane.Config{
		Listen: "127.0.0.1:0", Key: ctlKey,
		Window: 2 * time.Second, ThresholdBytes: threshold,
		HeartbeatEvery: 50 * time.Millisecond,
	})
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	mk := func(id string) *gateway.Gateway {
		g := gateway.New(gateway.Config{
			ID: id, Listen: "127.0.0.1:0", Upstream: up.Addr(), Control: p.Addr(),
			Key: ctlKey, TokenKey: tokenKey, LeaseTTL: 300 * time.Millisecond,
			ReportEvery: 20 * time.Millisecond,
		})
		if err := g.Start(ctx); err != nil {
			t.Fatal(err)
		}
		return g
	}
	e := &env{plane: p, gwA: mk("gw-a"), gwB: mk("gw-b"), cancel: cancel}
	if !p.WaitGateways(2, 2*time.Second) {
		t.Fatal("gateways did not register")
	}
	time.Sleep(100 * time.Millisecond) // first heartbeat
	t.Cleanup(cancel)
	return e
}

func dial(t *testing.T, gw *gateway.Gateway, sid string, rate int64) (*client.Result, func()) {
	t.Helper()
	c, r, err := client.Dial(gw.Addr(), sid, control.SessionToken(tokenKey, sid), rate)
	if err != nil {
		t.Fatalf("dial %s: %v", sid, err)
	}
	res := &client.Result{}
	done := make(chan struct{})
	go func() { *res = client.Drain(c, r, 0, 0, 5*time.Second); close(done) }()
	return res, func() { <-done }
}

func waitRecord(t *testing.T, p *controlplane.Plane, sid string) controlplane.Record {
	t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case r := <-p.Records():
			if r.SessionID == sid {
				return r
			}
		case <-timeout:
			t.Fatalf("no revoke record for %s", sid)
		}
	}
}

func TestManualRevokeClosesExistingFlowsOnAllGateways(t *testing.T) {
	e := setup(t, 1<<40)
	// Same session holds flows on both Active-Active gateways.
	resA, waitA := dial(t, e.gwA, "s1", 1<<20)
	resB, waitB := dial(t, e.gwB, "s1", 1<<20)
	time.Sleep(150 * time.Millisecond)

	e.plane.Revoke("s1", "soc-manual")
	rec := waitRecord(t, e.plane, "s1")
	waitA()
	waitB()

	if !resA.CutByRemote || !resB.CutByRemote {
		t.Fatalf("existing flows were not cut: A=%+v B=%+v", resA, resB)
	}
	if len(rec.Acks) != 2 {
		t.Fatalf("want ACK from both gateways, got %d", len(rec.Acks))
	}
	for gw, a := range rec.Acks {
		if a.Status != "applied" || a.FlowsClosed != 1 {
			t.Fatalf("%s ack = %+v", gw, a)
		}
	}
}

func TestReconnectAfterRevokeDenied(t *testing.T) {
	e := setup(t, 1<<40)
	e.plane.Revoke("s2", "soc-manual")
	waitRecord(t, e.plane, "s2")
	for _, gw := range []*gateway.Gateway{e.gwA, e.gwB} {
		_, _, err := client.Dial(gw.Addr(), "s2", control.SessionToken(tokenKey, "s2"), 1024)
		var de *client.DeniedError
		if !errors.As(err, &de) || de.Reason != "revoked" {
			t.Fatalf("want revoked, got %v", err)
		}
	}
}

func TestBulkTransferAutoRevoked(t *testing.T) {
	e := setup(t, 2<<20) // 2 MiB in 2 s
	res, wait := dial(t, e.gwA, "exfil", 8<<20)
	rec := waitRecord(t, e.plane, "exfil")
	wait()
	if rec.Reason != "bulk-transfer-threshold" || !res.CutByRemote {
		t.Fatalf("rec=%+v res=%+v", rec, res)
	}
}

func TestNormalTrafficNotRevoked(t *testing.T) {
	e := setup(t, 2<<20)
	c, r, err := client.Dial(e.gwA.Addr(), "normal", control.SessionToken(tokenKey, "normal"), 256<<10)
	if err != nil {
		t.Fatal(err)
	}
	res := client.Drain(c, r, 0, 0, 1500*time.Millisecond) // stops by deadline
	if res.CutByRemote {
		t.Fatalf("normal session was cut: %+v", res)
	}
	select {
	case rec := <-e.plane.Records():
		t.Fatalf("unexpected revoke: %+v", rec)
	default:
	}
}

func TestDuplicateEventAckedWithoutSideEffects(t *testing.T) {
	e := setup(t, 1<<40)
	id := e.plane.Revoke("s3", "soc-manual")
	waitRecord(t, e.plane, "s3")
	// Resend the very same event: gateways must ack it as a duplicate and
	// keep the session revoked.
	e.plane.Resend(control.Event{ID: id, SessionID: "s3", Epoch: 1, Action: control.ActionRevoke})
	time.Sleep(100 * time.Millisecond)
	if !e.gwA.Store().Revoked("s3") || !e.gwB.Store().Revoked("s3") {
		t.Fatal("session should remain revoked")
	}
}

func TestBadTokenDenied(t *testing.T) {
	e := setup(t, 1<<40)
	_, _, err := client.Dial(e.gwA.Addr(), "s4", "forged", 1024)
	var de *client.DeniedError
	if !errors.As(err, &de) || de.Reason != "bad-token" {
		t.Fatalf("want bad-token, got %v", err)
	}
}

func TestControlLossFailsClosed(t *testing.T) {
	e := setup(t, 1<<40)
	e.plane.Close() // control plane disappears
	time.Sleep(400 * time.Millisecond)
	_, _, err := client.Dial(e.gwA.Addr(), "s5", control.SessionToken(tokenKey, "s5"), 1024)
	var de *client.DeniedError
	if !errors.As(err, &de) || de.Reason != "control-lease-expired" {
		t.Fatalf("want control-lease-expired, got %v", err)
	}
}
