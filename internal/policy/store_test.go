package policy

import (
	"testing"
	"time"

	"github.com/trianglepotato/revokd/internal/control"
)

func ev(id string, epoch uint64, a control.Action) control.Event {
	return control.Event{ID: id, SessionID: "s1", Epoch: epoch, Action: a}
}

func TestDuplicateIsIdempotent(t *testing.T) {
	s := NewStore()
	now := time.Now()
	if got := s.Apply(ev("e1", 1, control.ActionRevoke), now); got != Applied {
		t.Fatalf("first apply = %s", got)
	}
	if got := s.Apply(ev("e1", 1, control.ActionRevoke), now); got != Duplicate {
		t.Fatalf("second apply = %s", got)
	}
	if !s.Revoked("s1") {
		t.Fatal("session should stay revoked")
	}
}

func TestOutOfOrderRestoreCannotUndoRevoke(t *testing.T) {
	s := NewStore()
	now := time.Now()
	// The control plane issued restore(epoch 1) then revoke(epoch 2), but the
	// network delivered them in reverse.
	if got := s.Apply(ev("revoke", 2, control.ActionRevoke), now); got != Applied {
		t.Fatalf("revoke = %s", got)
	}
	if got := s.Apply(ev("restore", 1, control.ActionRestore), now); got != Stale {
		t.Fatalf("late restore = %s, want stale", got)
	}
	if !s.Revoked("s1") {
		t.Fatal("late restore must not re-open the session")
	}
}

func TestNewerRestoreWins(t *testing.T) {
	s := NewStore()
	now := time.Now()
	s.Apply(ev("revoke", 1, control.ActionRevoke), now)
	if got := s.Apply(ev("restore", 2, control.ActionRestore), now); got != Applied {
		t.Fatalf("restore = %s", got)
	}
	if s.Revoked("s1") {
		t.Fatal("restore with newer epoch should re-open the session")
	}
}

func TestExpiredEventIgnored(t *testing.T) {
	s := NewStore()
	e := ev("old", 1, control.ActionRevoke)
	e.ExpiresAt = time.Now().Add(-time.Second)
	if got := s.Apply(e, time.Now()); got != Expired {
		t.Fatalf("got %s", got)
	}
	if s.Revoked("s1") {
		t.Fatal("expired event must not change policy")
	}
}
