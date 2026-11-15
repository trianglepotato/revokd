package envelope

import (
	"errors"
	"testing"
)

type payload struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := []byte("k")
	env, err := Seal(key, "event", payload{ID: "e1", Action: "revoke"})
	if err != nil {
		t.Fatal(err)
	}
	var got payload
	if err := Open(key, env, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "e1" || got.Action != "revoke" {
		t.Fatalf("got %+v", got)
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	key := []byte("k")
	env, _ := Seal(key, "event", payload{ID: "e1", Action: "revoke"})
	env.Payload = []byte(`{"id":"e1","action":"restore"}`)
	if err := Open(key, env, &payload{}); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("want ErrBadMAC, got %v", err)
	}
}

func TestTypeIsAuthenticated(t *testing.T) {
	key := []byte("k")
	env, _ := Seal(key, "heartbeat", payload{})
	env.Type = "event" // replay a heartbeat body as an event
	if err := Open(key, env, nil); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("want ErrBadMAC, got %v", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	env, _ := Seal([]byte("a"), "event", payload{ID: "e1"})
	if err := Open([]byte("b"), env, nil); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("want ErrBadMAC, got %v", err)
	}
}
