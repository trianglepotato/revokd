package control

import (
	"errors"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := []byte("k")
	env, err := Seal(key, TypeEvent, Event{ID: "e1", SessionID: "s1", Epoch: 1, Action: ActionRevoke})
	if err != nil {
		t.Fatal(err)
	}
	var got Event
	if err := Open(key, env, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "e1" || got.Action != ActionRevoke {
		t.Fatalf("got %+v", got)
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	key := []byte("k")
	env, _ := Seal(key, TypeEvent, Event{ID: "e1", SessionID: "victim", Action: ActionRevoke})
	env.Payload = []byte(`{"id":"e1","session_id":"victim","action":"restore"}`)
	if err := Open(key, env, &Event{}); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("want ErrBadMAC, got %v", err)
	}
}

func TestTypeIsAuthenticated(t *testing.T) {
	key := []byte("k")
	env, _ := Seal(key, TypeHeartbeat, Heartbeat{})
	env.Type = TypeEvent // replay a heartbeat body as an event
	if err := Open(key, env, nil); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("want ErrBadMAC, got %v", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	env, _ := Seal([]byte("a"), TypeEvent, Event{ID: "e1"})
	if err := Open([]byte("b"), env, nil); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("want ErrBadMAC, got %v", err)
	}
}
