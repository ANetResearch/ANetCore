package effect

import (
	"testing"

	"github.com/ANetResearch/ANetCore/tsir"
)

func TestVerifiable(t *testing.T) {
	cases := []struct {
		name string
		e    Effect
		want bool
	}{
		{"ok with record", Effect{Status: OK, Record: &tsir.EffectRecord{Metrics: map[string]float64{"power": 1}}}, true},
		{"ok without record", Effect{Status: OK}, false},
		{"unverified with record", Effect{Status: Unverified, Record: &tsir.EffectRecord{}}, false},
		{"failed", Effect{Status: Failed, Message: "boom"}, false},
	}
	for _, c := range cases {
		if got := c.e.Verifiable(); got != c.want {
			t.Errorf("%s: Verifiable() = %v, want %v", c.name, got, c.want)
		}
	}
}
