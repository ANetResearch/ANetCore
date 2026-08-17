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

func TestEvidenceOptional(t *testing.T) {
	// Evidence is additive: an effect without it behaves exactly as before.
	e := Effect{Status: OK, Record: &tsir.EffectRecord{Metrics: map[string]float64{"x": 1}}}
	if !e.Verifiable() {
		t.Fatal("verifiability must not depend on Evidence")
	}
	e.Evidence = &Evidence{
		Requested: "light.onoff=on", Protocol: "zigbee", NativeAck: true,
		ObservedState: "on", LatencyMS: 83, VerifyTrust: 2, AuthTrust: 1,
	}
	if !e.Verifiable() || e.Evidence.LatencyMS != 83 {
		t.Fatalf("evidence round-trip: %+v", e.Evidence)
	}
}
