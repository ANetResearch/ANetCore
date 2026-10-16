package identity

// Golden vector KSN-1 (core §5.2, KEL §7.1): a witness notice and a case for each step of
// VerifyNotice (C-51), each with the reason it is refused under.
//
// The file is generated twice, here and by the independent Python implementation in
// golden/py/gen_v016.py, and both must reproduce testdata/vec-ksn-1.json byte for byte (CI
// golden-xcheck). The Python side also judges every case with its own notice check.
//
//	go test ./identity -run TestKSN1Vector -update     rewrites the file
//	python3 golden/py/gen_v016.py check KSN-1           checks the Python side

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
)

const (
	ksnVID  = "KSN-1"
	ksnFile = "vec-ksn-1.json"
	// ksnObservedAt is when the witness observed the tip: after the KEL-2B agent's rot 2 (agentT0 +
	// 2 min), before the KEL-2A hub's dip (hubDipTS).
	ksnObservedAt = hubT0 + 400000
	ksnArrival    = ksnObservedAt + minute
	ksnHour       = 60 * minute
	// ksnEarlyObservedAt is a time the KEL-2A hub still signed with k0: before its planned rot 1
	// (hubT0 + 1 min), which retires key state 0 with the one-hour grace.
	ksnEarlyObservedAt = hubT0 + minute/2
	ksnPlannedRetired  = hubT0 + minute
	ksnAbout           = "Witness notices (L18): NoticeBody {0 t, 1 aid, 2 seq, 3 head, 4 observed_at, 5 witness}, " +
		"NoticeWire {1 body = coredet(NoticeBody), 2 env = aobj envelope {1 signer_aid, 2 key_state_seq, 3 alg = -8, 4 sig}}, " +
		"the signature Ed25519 over the body bytes. The valid notice is the KEL-2A hub's (W2) for the tip of the KEL-2B agent's " +
		"KEL up to its rot 2 (seq 2, which names W2), signed with KEL-2A k2 at key state 2. Each case gives the notice, the KEL " +
		"it is checked against (subject), the hub KELs the receiver holds (hub_kels: the hub AID asked for and the KEL " +
		"answered) and the arrival time; reason is what VerifyNotice must refuse it with (\"\" = accepted): the steps in order " +
		"are 1 decoding (witness-invalid), 2 a witness to confirm (witness-missing), 3 the tip (witness-mismatch), 4 the " +
		"signer (witness-invalid), 5 the witness hub's KEL and signature (witness-unknown, witness-invalid), 6 freshness " +
		"(witness-stale: observed at most 6 h before the arrival and at most 5 min after it). Keys are SHA-256 of their " +
		"labels: anet-golden/v016/KEL-2A/k<i>, anet-golden/v016/KEL-2B/k<i>, anet-golden/v016/KEL-2B/w1-k0 and " +
		"anet-golden/v016/KSN-1/<x|y>-k<i>."
)

type ksnVector struct {
	ID       string    `json:"id"`
	About    string    `json:"about"`
	KELs     []ksnKEL  `json:"kels"`
	Body     ksnBody   `json:"body"`
	BodyCBOR string    `json:"body_cbor"`
	Env      ksnEnv    `json:"env"`
	Notice   string    `json:"notice"`
	Cases    []ksnCase `json:"cases"`
}

type ksnKEL struct {
	Name  string `json:"name"`
	About string `json:"about"`
	AID   string `json:"aid"`
	KEL   string `json:"kel"`
}

type ksnBody struct {
	T          string `json:"t"`
	AID        string `json:"aid"`
	Seq        uint64 `json:"seq"`
	Head       string `json:"head"`
	ObservedAt uint64 `json:"observed_at"`
	Witness    string `json:"witness"`
}

type ksnEnv struct {
	SignerAID   string `json:"signer_aid"`
	KeyStateSeq uint64 `json:"key_state_seq"`
	Alg         int    `json:"alg"`
	Signer      string `json:"signer"`
	Sig         string `json:"sig"`
}

type ksnHubKEL struct {
	AID string `json:"aid"`
	KEL string `json:"kel"`
}

type ksnCase struct {
	Name    string      `json:"name"`
	Subject string      `json:"subject"`
	HubKELs []ksnHubKEL `json:"hub_kels"`
	Arrival uint64      `json:"arrival"`
	Notice  string      `json:"notice"`
	Reason  string      `json:"reason"`
}

// ksnKELs are the KELs of the vector, by name, in the order the file lists them.
type ksnKELs struct {
	names []string
	about map[string]string
	kel   map[string][]SignedEvent
}

func (k *ksnKELs) add(name, about string, kel []SignedEvent) {
	k.names = append(k.names, name)
	k.about[name] = about
	k.kel[name] = kel
}

func ksnKey(role string) ed25519.PrivateKey { return testKey("anet-golden/v016/KSN-1/" + role) }

// ksnBuildKELs builds the KELs of the vector: prefixes of KEL-2A and KEL-2B, the W1 hub, an agent X
// that names the KEL-2B agent as its witness, a hub Y, and A3 with one signature changed.
func ksnBuildKELs() *ksnKELs {
	k := &ksnKELs{about: map[string]string{}, kel: map[string][]SignedEvent{}}
	a, b := kel2A(), kel2B()
	k.add("A2", "the KEL-2A hub (W2) up to its rot 1: it ends before key state 2", clone(a[:2]))
	k.add("A3", "the KEL-2A hub (W2) up to its emergency rot 2: key state 2 (k2) is its tip", clone(a[:3]))
	k.add("A4", "the whole KEL-2A: its dip retires key state 2 urgently at "+u64s(hubDipTS), clone(a))
	k.add("B1", "the KEL-2B agent's icp alone: its witness is pending", clone(b[:1]))
	k.add("B2", "the KEL-2B agent up to its rot 1, which names W1", clone(b[:2]))
	k.add("B3", "the KEL-2B agent up to its rot 2, which names W2 (the KEL-2A hub)", clone(b[:3]))
	k.add("W1", "the W1 hub of KEL-2B (an icp)", w1KEL())
	x := []SignedEvent{signEvent(icpEvent(ksnKey("x-k0"), ksnKey("x-k1"), agentT0, ToadAgent), ksnKey("x-k0"))}
	x = extend(x, rotEvent(ksnKey("x-k1"), ksnKey("x-k2"), agentT0+minute, ToadAgent, b[0].EventID, false), ksnKey("x-k1"))
	k.add("X1", "an agent X whose rot 1 names the KEL-2B agent, an agent, as its witness", x)
	y := []SignedEvent{signEvent(icpEvent(ksnKey("y-k0"), ksnKey("y-k1"), hubT0, ToadHub), ksnKey("y-k0"))}
	y = extend(y, rotEvent(ksnKey("y-k1"), ksnKey("y-k2"), hubT0+minute, ToadHub, "", false), ksnKey("y-k1"))
	y = extend(y, rotEvent(ksnKey("y-k2"), ksnKey("y-k3"), hubT0+2*minute, ToadHub, "", false), ksnKey("y-k2"))
	k.add("Y3", "another hub Y up to its rot 2", y)
	bad := clone(a[:3])
	sig := append([]byte(nil), bad[2].Sig...)
	sig[0] ^= 0x01
	bad[2].Sig = sig
	k.add("A3-bad", "A3 with one bit of the signature of rot 2 changed: it does not replay", bad)
	return k
}

func u64s(v uint64) string { return strconv.FormatUint(v, 10) }

// ksnWire encodes a NoticeWire from the given body bytes and envelope map (keys as given).
func ksnWire(t testing.TB, body []byte, env map[uint64]any) []byte {
	t.Helper()
	b, err := coredet.Marshal(map[uint64]any{1: body, 2: env})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ksnEnvMap(signer string, seq uint64, sig []byte) map[uint64]any {
	return map[uint64]any{1: signer, 2: seq, 3: aobj.AlgEdDSA, 4: sig}
}

// ksnBodyMap is the body of a notice as a map, so that a case can change it freely.
func ksnBodyMap(aid string, seq uint64, head string, observedAt uint64, witness string) map[uint64]any {
	return map[uint64]any{0: NoticeType, 1: aid, 2: seq, 3: head, 4: observedAt, 5: witness}
}

func ksnMarshal(t testing.TB, v any) []byte {
	t.Helper()
	b, err := coredet.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ksnSigned is the notice of body bytes signed by key as signer at seq.
func ksnSigned(t testing.TB, body []byte, signer string, seq uint64, key ed25519.PrivateKey) []byte {
	t.Helper()
	return ksnWire(t, body, ksnEnvMap(signer, seq, ed25519.Sign(key, body)))
}

// ksnVectorFile is the KSN-1 file as this implementation generates it.
func ksnVectorFile(t testing.TB) []byte {
	t.Helper()
	k := ksnBuildKELs()
	ka, kb := vecKeys("KEL-2A"), vecKeys("KEL-2B")
	w1Key := testKey("anet-golden/v016/KEL-2B/w1-k0")
	aAID, bAID, w1AID := k.kel["A3"][0].EventID, k.kel["B3"][0].EventID, k.kel["W1"][0].EventID
	b3, b2, b1 := k.kel["B3"], k.kel["B2"], k.kel["B1"]
	tip, tip1 := b3[2].EventID, b2[1].EventID

	v := ksnVector{ID: ksnVID, About: ksnAbout}
	for _, n := range k.names {
		v.KELs = append(v.KELs, ksnKEL{Name: n, About: k.about[n], AID: k.kel[n][0].EventID, KEL: hex.EncodeToString(mustMarshal(t, k.kel[n]))})
	}
	bodyMap := ksnBodyMap(bAID, 2, tip, ksnObservedAt, aAID)
	body := ksnMarshal(t, bodyMap)
	notice := ksnSigned(t, body, aAID, 2, ka[2])
	v.Body = ksnBody{T: NoticeType, AID: bAID, Seq: 2, Head: tip, ObservedAt: ksnObservedAt, Witness: aAID}
	v.BodyCBOR = hex.EncodeToString(body)
	v.Env = ksnEnv{SignerAID: aAID, KeyStateSeq: 2, Alg: aobj.AlgEdDSA, Signer: "anet-golden/v016/KEL-2A/k2",
		Sig: hex.EncodeToString(ed25519.Sign(ka[2], body))}
	v.Notice = hex.EncodeToString(notice)

	hubs := func(pairs ...string) []ksnHubKEL {
		out := []ksnHubKEL{}
		for i := 0; i+1 < len(pairs); i += 2 {
			out = append(out, ksnHubKEL{AID: pairs[i], KEL: pairs[i+1]})
		}
		return out
	}
	held := hubs(aAID, "A3")
	add := func(name, subject string, hubKELs []ksnHubKEL, arrival uint64, n []byte, reason string) {
		v.Cases = append(v.Cases, ksnCase{Name: name, Subject: subject, HubKELs: hubKELs, Arrival: arrival,
			Notice: hex.EncodeToString(n), Reason: reason})
	}
	// signedBody signs a changed body as the witness at key state 2.
	signedBody := func(over map[uint64]any, drop ...uint64) []byte {
		m := map[uint64]any{}
		for k, v := range bodyMap {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		for _, k := range drop {
			delete(m, k)
		}
		return ksnSigned(t, ksnMarshal(t, m), aAID, 2, ka[2])
	}
	sig := ed25519.Sign(ka[2], body)
	envWith := func(over map[uint64]any) map[uint64]any {
		m := ksnEnvMap(aAID, 2, sig)
		for k, v := range over {
			m[k] = v
		}
		return m
	}

	// Accepted.
	add("ok: the notice for the tip, signed by its witness at the witness's current key", "B3", held, ksnArrival, notice, "")
	add("ok: observed exactly 6 h before the arrival", "B3", held, ksnObservedAt+6*ksnHour, notice, "")
	add("ok: observed exactly 5 min after the arrival", "B3", held, ksnObservedAt-5*minute, notice, "")
	add("ok: the witness's key state is retired later, by its dip, exactly at the arrival", "B3",
		hubs(aAID, "A4"), hubDipTS, notice, "")
	add("ok: an older prefix of the KEL, with a notice from the witness that prefix names", "B2", hubs(aAID, "A3", w1AID, "W1"),
		ksnArrival, ksnSigned(t, ksnMarshal(t, ksnBodyMap(bAID, 1, tip1, ksnObservedAt, w1AID)), w1AID, 0, w1Key), "")
	// A notice the witness signed with k0 before its planned rot 1 retired key state 0.
	early := ksnSigned(t, ksnMarshal(t, ksnBodyMap(bAID, 2, tip, ksnEarlyObservedAt, aAID)), aAID, 0, ka[0])
	add("ok: the witness's key state was retired by its planned rot 1, and the arrival is exactly 1 h after it", "B3", held,
		ksnPlannedRetired+ksnHour, early, "")

	// Step 1: decoding.
	add("a text string, not a NoticeWire", "B3", held, ksnArrival, ksnMarshal(t, "a notice"), "witness-invalid")
	add("NoticeWire with an unregistered key 3", "B3", held, ksnArrival,
		ksnMarshal(t, map[uint64]any{1: body, 2: envWith(nil), 3: "x"}), "witness-invalid")
	add("NoticeWire without its signature envelope (key 2)", "B3", held, ksnArrival,
		ksnMarshal(t, map[uint64]any{1: body}), "witness-invalid")
	add("NoticeWire with its keys out of CoreDet order", "B3", held, ksnArrival,
		ksnInOrder(t, []uint64{2, 1}, map[uint64]any{1: body, 2: envWith(nil)}), "witness-invalid")
	add("body with an unregistered key 6", "B3", held, ksnArrival, signedBody(map[uint64]any{6: "x"}), "witness-invalid")
	add("body without key 0", "B3", held, ksnArrival, signedBody(nil, 0), "witness-invalid")
	add("body of type anet.ksn/2", "B3", held, ksnArrival, signedBody(map[uint64]any{0: "anet.ksn/2"}), "witness-invalid")
	add("body with observed_at as a text string", "B3", held, ksnArrival,
		signedBody(map[uint64]any{4: u64s(ksnObservedAt)}), "witness-invalid")
	{
		odd := ksnInOrder(t, []uint64{1, 0, 2, 3, 4, 5}, bodyMap)
		add("body with its keys out of CoreDet order, signed as written", "B3", held, ksnArrival,
			ksnSigned(t, odd, aAID, 2, ka[2]), "witness-invalid")
	}
	{
		arr := ksnMarshal(t, []any{NoticeType, bAID, 2, tip, ksnObservedAt, aAID})
		add("body an array, not a map, signed as written", "B3", held, ksnArrival, ksnSigned(t, arr, aAID, 2, ka[2]), "witness-invalid")
	}
	add("signature envelope with alg -7", "B3", held, ksnArrival,
		ksnWire(t, body, envWith(map[uint64]any{3: -7})), "witness-invalid")
	add("signature of 63 bytes", "B3", held, ksnArrival, ksnWire(t, body, envWith(map[uint64]any{4: sig[:63]})), "witness-invalid")
	add("signature envelope with a preimage reference (key 5)", "B3", held, ksnArrival,
		ksnWire(t, body, envWith(map[uint64]any{5: "ref"})), "witness-invalid")

	// Step 2: a witness to confirm.
	add("the KEL is an agent's whose witness is pending (its icp alone)", "B1", held, ksnArrival,
		ksnSigned(t, ksnMarshal(t, ksnBodyMap(bAID, 0, b1[0].EventID, ksnObservedAt, aAID)), aAID, 2, ka[2]), "witness-missing")
	add("the KEL is a hub's (toad 0)", "A3", held, ksnArrival,
		ksnSigned(t, ksnMarshal(t, ksnBodyMap(aAID, 2, k.kel["A3"][2].EventID, ksnObservedAt, aAID)), aAID, 2, ka[2]), "witness-missing")

	// Step 3: the tip.
	add("the notice is about another AID", "B3", held, ksnArrival, signedBody(map[uint64]any{1: w1AID}), "witness-mismatch")
	add("the notice states an older seq and head of the KEL", "B3", held, ksnArrival,
		signedBody(map[uint64]any{2: uint64(1), 3: tip1}), "witness-mismatch")
	add("the notice states the tip's seq with another event's id", "B3", held, ksnArrival,
		signedBody(map[uint64]any{3: tip1}), "witness-mismatch")

	// Step 4: the signer.
	add("the notice is from a hub the tip does not name, signed by that hub", "B3", hubs(aAID, "A3", w1AID, "W1"), ksnArrival,
		ksnSigned(t, ksnMarshal(t, ksnBodyMap(bAID, 2, tip, ksnObservedAt, w1AID)), w1AID, 0, w1Key), "witness-invalid")
	add("signed by the tip's witness, with an envelope that names another signer", "B3", hubs(aAID, "A3", w1AID, "W1"), ksnArrival,
		ksnWire(t, body, ksnEnvMap(w1AID, 2, sig)), "witness-invalid")

	// Step 5: the witness hub's KEL and signature.
	add("no KEL is held for the witness", "B3", hubs(), ksnArrival, notice, "witness-unknown")
	add("the KEL held for the witness ends before the notice's key state", "B3", hubs(aAID, "A2"), ksnArrival, notice, "witness-unknown")
	add("the KEL held for the witness is another hub's", "B3", hubs(aAID, "Y3"), ksnArrival, notice, "witness-invalid")
	add("the KEL held for the witness does not replay", "B3", hubs(aAID, "A3-bad"), ksnArrival, notice, "witness-invalid")
	add("the witness is an agent (toad 1), not a hub", "X1", hubs(bAID, "B3"), ksnArrival,
		ksnSigned(t, ksnMarshal(t, ksnBodyMap(k.kel["X1"][0].EventID, 1, k.kel["X1"][1].EventID, ksnObservedAt, bAID)), bAID, 2, kb[2]),
		"witness-invalid")
	add("one bit of the signature changed", "B3", held, ksnArrival,
		ksnWire(t, body, envWith(map[uint64]any{4: flipBit(sig)})), "witness-invalid")
	add("signed at a key state of the witness retired before observed_at", "B3", held, ksnArrival,
		ksnSigned(t, body, aAID, 1, ka[1]), "witness-invalid")
	add("the witness's key state was retired by its dip 1 ms before the arrival", "B3", hubs(aAID, "A4"), hubDipTS+1, notice, "witness-invalid")
	add("the witness's key state was retired by its planned rot 1, 1 h and 1 ms before the arrival", "B3", held,
		ksnPlannedRetired+ksnHour+1, early, "witness-invalid")

	// Step 6: freshness.
	add("observed 6 h and 1 ms before the arrival", "B3", held, ksnObservedAt+6*ksnHour+1, notice, "witness-stale")
	add("observed 5 min and 1 ms after the arrival", "B3", held, ksnObservedAt-5*minute-1, notice, "witness-stale")

	// The first failing step decides.
	add("about an older seq and stale: the tip is checked first", "B3", held, ksnObservedAt+7*ksnHour,
		signedBody(map[uint64]any{2: uint64(1), 3: tip1}), "witness-mismatch")
	add("no KEL held for the witness and stale: the witness's KEL is looked up first", "B3", hubs(), ksnObservedAt+7*ksnHour,
		notice, "witness-unknown")
	add("from a hub the tip does not name, and no KEL held for that hub: the signer is checked first", "B3", held, ksnArrival,
		ksnSigned(t, ksnMarshal(t, ksnBodyMap(bAID, 2, tip, ksnObservedAt, w1AID)), w1AID, 0, w1Key), "witness-invalid")
	add("a KEL whose witness is pending, with the notice for another tip: the witness to confirm is checked first", "B1", held,
		ksnArrival, notice, "witness-missing")
	add("a body with an unregistered key, about an older seq: decoding is checked first", "B3", held, ksnArrival,
		signedBody(map[uint64]any{2: uint64(1), 3: tip1, 6: "x"}), "witness-invalid")
	return encodeVector(t, v)
}

func flipBit(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[0] ^= 0x01
	return out
}

// ksnInOrder encodes m as a CBOR map with its keys in the given order: a map that is not in CoreDet
// form when the order is not ascending.
func ksnInOrder(t testing.TB, order []uint64, m map[uint64]any) []byte {
	t.Helper()
	out := []byte{0xa0 | byte(len(order))}
	for _, k := range order {
		out = append(out, ksnMarshal(t, k)...)
		out = append(out, ksnMarshal(t, m[k])...)
	}
	return out
}

// The committed KSN-1 is what this implementation generates.
func TestKSN1Vector(t *testing.T) {
	want := ksnVectorFile(t)
	path := filepath.Join("testdata", ksnFile)
	if *updateVectors {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (generate with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from what Go generates (regenerate with -update and check the diff)", path)
	}
}

// noticeReason names a VerifyNotice result the way the vector does: the seal reason of its step
// (C-56), "" for an accepted notice.
func noticeReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNoticeInvalid):
		return "witness-invalid"
	case errors.Is(err, ErrNoticeMissing):
		return "witness-missing"
	case errors.Is(err, ErrNoticeMismatch):
		return "witness-mismatch"
	case errors.Is(err, ErrNoticeUnknownWitness):
		return "witness-unknown"
	case errors.Is(err, ErrNoticeStale):
		return "witness-stale"
	}
	return "unexpected: " + err.Error()
}

// TestKSN_1 checks the committed KSN-1 from the file alone: the valid notice is the body signed by
// the KEL-2A hub's k2 at key state 2, SignNotice writes the same bytes, and every case gets its
// reason from VerifyNotice (M8, M9, M11 turn it red).
func TestKSN_1(t *testing.T) {
	var v ksnVector
	readVector(t, ksnFile, &v)
	kels := map[string][]SignedEvent{}
	for _, k := range v.KELs {
		kel, err := UnmarshalKEL(mustHex(t, k.KEL))
		if err != nil {
			t.Fatalf("%s: %v", k.Name, err)
		}
		if kel[0].EventID != k.AID {
			t.Fatalf("%s: the KEL is %s's, recorded %s", k.Name, kel[0].EventID, k.AID)
		}
		kels[k.Name] = kel
	}
	// The valid notice.
	notice := mustHex(t, v.Notice)
	body, env, err := DecodeNotice(notice)
	if err != nil {
		t.Fatal(err)
	}
	want := NoticeBody{Type: v.Body.T, AID: v.Body.AID, Seq: v.Body.Seq, Head: v.Body.Head, ObservedAt: v.Body.ObservedAt, Witness: v.Body.Witness}
	if body != want || env.SignerAID != v.Env.SignerAID || env.KeyStateSeq != v.Env.KeyStateSeq || env.Alg != v.Env.Alg ||
		hex.EncodeToString(env.Sig) != v.Env.Sig || env.PreimageRef != "" {
		t.Fatalf("decoded %+v %+v, recorded %+v %+v", body, env, v.Body, v.Env)
	}
	if b, err := coredet.Marshal(body); err != nil || hex.EncodeToString(b) != v.BodyCBOR {
		t.Fatalf("body bytes %x (%v), recorded %s", b, err, v.BodyCBOR)
	}
	key := testKey(v.Env.Signer)
	if !ed25519.Verify(pubOf(key), mustHex(t, v.BodyCBOR), env.Sig) {
		t.Fatal("the signature is not the recorded signer's")
	}
	// SignNotice writes the same notice as the witness at that key state.
	hub := &snapshot{aid: v.Env.SignerAID, seq: v.Env.KeyStateSeq, kel: kels["A3"], key: key}
	got, err := SignNotice(hub, NoticeBody{AID: want.AID, Seq: want.Seq, Head: want.Head, ObservedAt: want.ObservedAt})
	if err != nil || !bytes.Equal(got, notice) {
		t.Fatalf("SignNotice gives %x (%v)", got, err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("no cases")
	}
	seen := map[string]bool{}
	for _, c := range v.Cases {
		seen[c.Reason] = true
		held := map[string][]SignedEvent{}
		for _, h := range c.HubKELs {
			kel, ok := kels[h.KEL]
			if !ok {
				t.Fatalf("%s: no KEL %q", c.Name, h.KEL)
			}
			held[h.AID] = kel
		}
		src := func(aid string) ([]SignedEvent, bool) {
			kel, ok := held[aid]
			return kel, ok
		}
		subject, ok := kels[c.Subject]
		if !ok {
			t.Fatalf("%s: no KEL %q", c.Name, c.Subject)
		}
		err := VerifyNotice(mustHex(t, c.Notice), subject, src, c.Arrival)
		if got := noticeReason(err); got != c.Reason {
			t.Errorf("%s: %q (%v), want %q", c.Name, got, err, c.Reason)
		}
	}
	for _, r := range []string{"", "witness-invalid", "witness-missing", "witness-mismatch", "witness-unknown", "witness-stale"} {
		if !seen[r] {
			t.Errorf("no case with reason %q", r)
		}
	}
}
