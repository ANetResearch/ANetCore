package effect_test

// Fuzz target for the effect envelope decoder (ANet docs/notes/0033).

import (
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/effect"
	"github.com/ANetResearch/ANetCore/tsir"
)

func FuzzEffect(f *testing.F) {
	b, err := coredet.Marshal(effect.Effect{Status: effect.OK, Message: "m",
		Record:   &tsir.EffectRecord{Metrics: map[string]float64{"x": 1.5}, Tests: []tsir.TestResult{{ID: "t", Status: 1}}},
		Evidence: &effect.Evidence{Requested: "a", Protocol: "zigbee", NativeAck: true, LatencyMS: 3, VerifyTrust: 2, Quirk: "q"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		var e effect.Effect
		if coredet.Unmarshal(b, &e) != nil {
			return
		}
		if e.Verifiable() != (e.Status == effect.OK && e.Record != nil) {
			t.Fatal("Verifiable disagrees with its definition")
		}
		rb, err := coredet.Marshal(e)
		if err != nil {
			return // NaN or ±Inf in a metric: CoreDet refuses to encode it (C-R1)
		}
		var back effect.Effect
		if err := coredet.Unmarshal(rb, &back); err != nil {
			t.Fatalf("re-encoded effect does not decode: %v", err)
		}
		rb2, err := coredet.Marshal(back)
		if err != nil || string(rb2) != string(rb) {
			t.Fatalf("effect encoding is not a fixed point: %v", err)
		}
	})
}
