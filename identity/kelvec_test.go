package identity

// Golden vectors KEL-2A, KEL-2B and KEL-2N (core §5.2, KEL §7.1).
//
// KEL-2A and KEL-2B are generated twice, here and by the independent Python implementation in
// golden/py/gen_v016.py, and both must reproduce testdata/vec-kel-2a.json and vec-kel-2b.json
// byte for byte (CI golden-xcheck). KEL-2N is generated here only: the negative cases and the
// error text each must fail with.
//
//	go test ./identity -run TestKELVectors -update     rewrites the three files
//	python3 golden/py/gen_v016.py check KEL-2A KEL-2B    checks the Python side

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateVectors = flag.Bool("update", false, "rewrite the KEL vectors in testdata")

type vecKey struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	Pub   string `json:"pub"`
}

type vecWitness struct {
	Name   string   `json:"name"`
	AID    string   `json:"aid"`
	Labels []string `json:"labels"`
	KEL    string   `json:"kel"`
}

type vecEvent struct {
	Seq      uint64 `json:"seq"`
	T        string `json:"t"`
	Signer   string `json:"signer"`
	Preimage string `json:"preimage"`
	EventID  string `json:"event_id"`
	Sig      string `json:"sig"`
}

type vecState struct {
	Seq             uint64 `json:"seq"`
	Status          string `json:"status"`
	Key             string `json:"key"`
	Toad            uint64 `json:"toad"`
	Witness         string `json:"witness"`
	SupersededAt    uint64 `json:"superseded_at"`
	RetiredUrgently bool   `json:"retired_urgently"`
}

type kelVector struct {
	ID        string       `json:"id"`
	About     string       `json:"about"`
	Keys      []vecKey     `json:"keys"`
	Witnesses []vecWitness `json:"witnesses"`
	AID       string       `json:"aid"`
	Events    []vecEvent   `json:"events"`
	KEL       string       `json:"kel"`
	States    []vecState   `json:"states"`
}

type negVector struct {
	Name  string `json:"name"`
	KEL   string `json:"kel"`
	Error string `json:"error"`
}

type negVectors struct {
	ID    string      `json:"id"`
	About string      `json:"about"`
	Cases []negVector `json:"cases"`
}

const (
	about2A = "KEL v2 hub identity (toad 0): icp, rot 1 (setup-recovery), rot 2 (emergency), dip 3. " +
		"Key seeds are SHA-256 of the labels. The icp is signed by k0, every rot and dip by the key it reveals. " +
		"preimage is coredet(KeyEvent) (L17), event_id its CID, kel is MarshalKEL."
	about2B = "KEL v2 agent identity (toad 1): icp (witness pending), rot 1 (designates W1), rot 2 (moves to W2), dip 3. " +
		"W1 is the hub incepted from the labels given, W2 the KEL-2A hub. " +
		"Key seeds are SHA-256 of the labels. The icp is signed by k0, every rot and dip by the key it reveals. " +
		"preimage is coredet(KeyEvent) (L17), event_id its CID, kel is MarshalKEL."
	about2N = "KEL v2 negative cases: each kel (MarshalKEL bytes, or bytes written by hand for the encoding cases) " +
		"must fail UnmarshalKEL or Replay with exactly the error text given. Keys are those of KEL-2A and KEL-2B " +
		"and the label anet-golden/v016/KEL-2N/attacker."
)

// buildVector writes a valid KEL out as a vector. keys name the KEL's keys in order k0..k3.
func buildVector(t testing.TB, id, about string, kel []SignedEvent, keys []namedKey, wit []vecWitness) kelVector {
	t.Helper()
	v := kelVector{ID: id, About: about, Witnesses: wit, AID: kel[0].EventID}
	if v.Witnesses == nil {
		v.Witnesses = []vecWitness{}
	}
	byPub := map[string]string{}
	for _, k := range keys {
		pub := hex.EncodeToString(pubOf(k.key))
		v.Keys = append(v.Keys, vecKey{Name: k.name, Label: k.label, Pub: pub})
		byPub[pub] = k.name
	}
	for _, se := range kel {
		pre, err := preimage(se.Event)
		if err != nil {
			t.Fatal(err)
		}
		v.Events = append(v.Events, vecEvent{Seq: se.Event.Seq, T: string(se.Event.Type),
			Signer: byPub[hex.EncodeToString(se.Event.Keys[0])], Preimage: hex.EncodeToString(pre),
			EventID: se.EventID, Sig: hex.EncodeToString(se.Sig)})
	}
	v.KEL = hex.EncodeToString(mustMarshal(t, kel))
	states, err := Replay(kel)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range states {
		key := ""
		if len(s.CurrentKeys) == 1 {
			key = byPub[hex.EncodeToString(s.CurrentKeys[0])]
		}
		v.States = append(v.States, vecState{Seq: s.KeyStateSeq, Status: s.Status, Key: key, Toad: s.Toad,
			Witness: s.Witness, SupersededAt: s.SupersededAt, RetiredUrgently: s.RetiredUrgently})
	}
	return v
}

type namedKey struct {
	name, label string
	key         ed25519.PrivateKey
}

func namedKeys(id string) []namedKey {
	var out []namedKey
	for i, k := range vecKeys(id) {
		name := "k" + string(rune('0'+i))
		out = append(out, namedKey{name: name, label: "anet-golden/v016/" + id + "/" + name, key: k})
	}
	return out
}

// vectorFiles are the three files and their contents as this implementation generates them.
func vectorFiles(t testing.TB) map[string][]byte {
	t.Helper()
	a := buildVector(t, "KEL-2A", about2A, kel2A(), namedKeys("KEL-2A"), nil)
	w1 := w1KEL()
	b := buildVector(t, "KEL-2B", about2B, kel2B(), namedKeys("KEL-2B"), []vecWitness{
		{Name: "W1", AID: w1[0].EventID, Labels: []string{"anet-golden/v016/KEL-2B/w1-k0", "anet-golden/v016/KEL-2B/w1-k1"},
			KEL: hex.EncodeToString(mustMarshal(t, w1))},
		{Name: "W2", AID: a.AID, Labels: []string{}, KEL: a.KEL},
	})
	n := negVectors{ID: "KEL-2N", About: about2N}
	for _, c := range negativeCases(t) {
		n.Cases = append(n.Cases, negVector{Name: c.name, KEL: hex.EncodeToString(c.kel), Error: c.err})
	}
	return map[string][]byte{
		"vec-kel-2a.json": encodeVector(t, a),
		"vec-kel-2b.json": encodeVector(t, b),
		"vec-kel-2n.json": encodeVector(t, n),
	}
}

// encodeVector is the JSON form both generators write: two-space indent, no HTML escaping, a
// final newline (Python: json.dumps(v, indent=2) + "\n").
func encodeVector(t testing.TB, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The committed vectors are what this implementation generates.
func TestKELVectors(t *testing.T) {
	for name, want := range vectorFiles(t) {
		path := filepath.Join("testdata", name)
		if *updateVectors {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (generate with -update)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from what Go generates (regenerate with -update and check the diff)", path)
		}
	}
}

// The committed KEL-2A and KEL-2B bytes replay to the states they record, independently of how
// they were generated.
func TestKEL2AAnd2BVectorsReplay(t *testing.T) {
	for _, name := range []string{"vec-kel-2a.json", "vec-kel-2b.json"} {
		var v kelVector
		readVector(t, name, &v)
		b, err := hex.DecodeString(v.KEL)
		if err != nil {
			t.Fatal(err)
		}
		states, err := replayBytes(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(states) != len(v.States) || len(v.Events) != len(states) {
			t.Fatalf("%s: %d states, %d recorded", name, len(states), len(v.States))
		}
		keyName := map[string]string{}
		for _, k := range v.Keys {
			keyName[k.Pub] = k.Name
		}
		for i, s := range states {
			w := v.States[i]
			key := ""
			if len(s.CurrentKeys) == 1 {
				key = keyName[hex.EncodeToString(s.CurrentKeys[0])]
			}
			if s.AID != v.AID || s.KeyStateSeq != w.Seq || s.Status != w.Status || key != w.Key || s.Toad != w.Toad ||
				s.Witness != w.Witness || s.SupersededAt != w.SupersededAt || s.RetiredUrgently != w.RetiredUrgently {
				t.Errorf("%s state %d: %+v, recorded %+v", name, i, s, w)
			}
			if s.LastEventID != v.Events[i].EventID {
				t.Errorf("%s event %d id %s, recorded %s", name, i, s.LastEventID, v.Events[i].EventID)
			}
		}
	}
}

// TestKEL2NVectors: every committed KEL-2N case fails with its recorded text (M1–M7, M29, M30 turn
// it red).
func TestKEL2NVectors(t *testing.T) {
	var v negVectors
	readVector(t, "vec-kel-2n.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range v.Cases {
		b, err := hex.DecodeString(c.KEL)
		if err != nil {
			t.Fatal(err)
		}
		_, err = replayBytes(b)
		if err == nil {
			t.Errorf("%s: replayed", c.Name)
			continue
		}
		if err.Error() != c.Error {
			t.Errorf("%s:\n got  %q\n want %q", c.Name, err.Error(), c.Error)
		}
	}
}

func readVector(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}
