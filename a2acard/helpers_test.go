package a2acard

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"testing"

	"github.com/ANetResearch/ANetCore/identity"
)

// t0 is 2026-01-01T00:00:00Z in unix milliseconds; the "now" of most tests.
const t0 uint64 = 1767225600000

func dec(n uint64) string { return strconv.FormatUint(n, 10) }

func jku(aid string) string { return "https://hub.example.org/agents/" + aid + "/jwks.json" }

// baseCard is a minimal valid anet network card for aid, as a generic JSON tree so tests can
// change any member.
func baseCard(aid string) map[string]any {
	return map[string]any{
		"name":        "Test Agent",
		"description": "An agent used by the a2acard tests.",
		"version":     "1.0.0",
		"supportedInterfaces": []any{
			map[string]any{
				"url":             "https://hub.example.org/relay/v2",
				"protocolBinding": BindingRelayURI,
				"protocolVersion": "1.0",
				"tenant":          aid,
			},
		},
		"capabilities": map[string]any{
			"streaming":         false,
			"pushNotifications": false,
			"extensions": []any{
				map[string]any{
					"uri": ExtCardURI,
					"params": map[string]any{
						"aid":       aid,
						"seq":       dec(t0),
						"issuedAt":  dec(t0),
						"notBefore": dec(t0 - 60_000),
					},
				},
			},
		},
		"defaultInputModes":  []any{"text/plain"},
		"defaultOutputModes": []any{"text/plain"},
		"skills": []any{
			map[string]any{
				"id":          "echo",
				"name":        "Echo",
				"description": "Returns the input text.",
				"tags":        []any{"text", "echo"},
			},
		},
	}
}

func params(card map[string]any) map[string]any {
	return extensions(card)[0].(map[string]any)["params"].(map[string]any)
}

func extensions(card map[string]any) []any {
	return card["capabilities"].(map[string]any)["extensions"].([]any)
}

func skill(card map[string]any, i int) map[string]any {
	return card["skills"].([]any)[i].(map[string]any)
}

func iface(card map[string]any, i int) map[string]any {
	return card["supportedInterfaces"].([]any)[i].(map[string]any)
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signCard signs card under c's current key state.
func signCard(t *testing.T, card map[string]any, c *identity.Controller) []byte {
	t.Helper()
	out, err := SignWithController(marshal(t, card), c, jku(c.AID()))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// signAs signs card with an explicit key and kid.
func signAs(t *testing.T, card map[string]any, priv ed25519.PrivateKey, kid string) []byte {
	t.Helper()
	out, err := Sign(marshal(t, card), priv, kid, "")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// edit decodes a signed card, applies f and re-encodes it, leaving the signatures untouched.
func edit(t *testing.T, cardJSON []byte, f func(map[string]any)) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(cardJSON))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	f(m)
	return marshal(t, m)
}

// resolver serves the KELs of the given controllers and counts calls.
type resolver struct {
	kels  map[string][]identity.SignedEvent
	calls int
}

func newResolver(cs ...*identity.Controller) *resolver {
	r := &resolver{kels: map[string][]identity.SignedEvent{}}
	for _, c := range cs {
		r.kels[c.AID()] = c.KEL()
	}
	return r
}

var errNoKEL = errors.New("test resolver: no KEL for this AID")

func (r *resolver) resolve(aid string) ([]identity.SignedEvent, error) {
	r.calls++
	kel, ok := r.kels[aid]
	if !ok {
		return nil, errNoKEL
	}
	return kel, nil
}

func incept(t *testing.T) *identity.Controller {
	t.Helper()
	c, err := identity.Incept()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("got no error, want %s", code)
	}
	if !IsCode(err, code) {
		t.Fatalf("got %v, want code %s", err, code)
	}
}
