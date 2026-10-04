package identity

// SenderKeyUsable (C-13), witness notices (C-50, C-51) and MergedEmergency (D-44). Each step of
// VerifyNotice also has its cases in KSN-1 (ksnvec_test.go).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
)

// ---- C-13: SenderKeyUsable (P6) ------------------------------------------------------------------

func TestSenderKeyUsable(t *testing.T) {
	states, err := Replay(kel2A())
	if err != nil {
		t.Fatal(err)
	}
	// KEL-2A: state 0 retired by the planned rot 1, state 1 by the emergency rot 2, state 2 by the
	// dip, state 3 the dip.
	cases := []struct {
		name    string
		ks      KeyState
		arrival uint64
		want    bool
	}{
		{"planned, before the rotation", states[0], hubT0 + minute - 1, true},
		{"planned, at SupersededAt + 1 h", states[0], hubT0 + minute + RotationGrace, true},
		{"planned, 1 ms past the grace", states[0], hubT0 + minute + RotationGrace + 1, false},
		{"emergency, arrival long before the rotation", states[1], hubT0 + 1, false},
		{"emergency, arrival just before the rotation", states[1], hubT0 + 2*minute - 1, false},
		{"emergency, arrival at the rotation", states[1], hubT0 + 2*minute, false},
		{"retired by the dip, arrival before it", states[2], hubDipTS - 1, false},
		{"the dip's own state", states[3], hubDipTS, false},
	}
	for _, c := range cases {
		if got := SenderKeyUsable(c.ks, c.arrival); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// The active tip of a KEL is usable at any arrival.
	tip, err := Replay(kel2A()[:3])
	if err != nil {
		t.Fatal(err)
	}
	for _, arrival := range []uint64{0, 1, hubT0, math.MaxUint64} {
		if !SenderKeyUsable(tip[2], arrival) {
			t.Fatalf("the active state at %d", arrival)
		}
	}
}

// P6 (C-13): for any key state and arrival, SenderKeyUsable is false for a state retired urgently and
// RetiredUsableAt for every other.
func TestSenderKeyUsableProperty(t *testing.T) {
	r := rand.New(rand.NewSource(13))
	statuses := []string{StatusActive, StatusRotated, StatusDeactivated, ""}
	for i := 0; i < 200000; i++ {
		ks := KeyState{Status: statuses[r.Intn(len(statuses))], RetiredUrgently: r.Intn(2) == 0}
		switch r.Intn(3) {
		case 0:
			ks.SupersededAt = r.Uint64()
		case 1:
			ks.SupersededAt = uint64(r.Intn(1000))
		default:
			ks.SupersededAt = math.MaxUint64 - uint64(r.Intn(1000))
		}
		var arrival uint64
		switch r.Intn(4) {
		case 0:
			arrival = r.Uint64()
		case 1:
			arrival = ks.SupersededAt - uint64(r.Intn(3)) // before it, by wrapping when it is small
		case 2:
			arrival = ks.SupersededAt + RotationGrace - 1 + uint64(r.Intn(3))
		default:
			arrival = uint64(r.Intn(3)) + 1
		}
		got := SenderKeyUsable(ks, arrival)
		want := !ks.RetiredUrgently && RetiredUsableAt(ks, arrival)
		if got != want {
			t.Fatalf("%+v at %d: %v, want %v", ks, arrival, got, want)
		}
		if ks.RetiredUrgently && got {
			t.Fatalf("%+v at %d: an urgently retired state is usable", ks, arrival)
		}
	}
}

// SenderKeyUsable has no grace of its own: the only grace is RetiredUsableAt's (C-13).
func TestSenderKeyUsableCallsOnlyRetiredUsableAt(t *testing.T) {
	b, err := os.ReadFile("identity.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "func SenderKeyUsable(")
	if i < 0 {
		t.Fatal("no SenderKeyUsable")
	}
	body := src[i:]
	body = body[:strings.Index(body, "\n}\n")]
	if strings.Contains(body, "RotationGrace") || strings.Contains(body, "SupersededAt") || !strings.Contains(body, "RetiredUsableAt(ks, arrival)") {
		t.Fatalf("SenderKeyUsable computes a grace of its own:\n%s", body)
	}
}

// ---- C-50, C-51: SignNotice, DecodeNotice, VerifyNotice --------------------------------------------

// noticeHub is the KEL-2A hub at key state 2 (k2, its tip in kel2A()[:3]).
func noticeHub() *snapshot {
	kel := kel2A()[:3]
	return &snapshot{aid: kel[0].EventID, seq: 2, kel: kel, key: vecKeys("KEL-2A")[2]}
}

func noticeFor(t testing.TB, s Signer, kel []SignedEvent, observedAt uint64) []byte {
	t.Helper()
	tip := kel[len(kel)-1]
	n, err := SignNotice(s, NoticeBody{AID: kel[0].EventID, Seq: tip.Event.Seq, Head: tip.EventID, ObservedAt: observedAt})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSignNotice(t *testing.T) {
	hub, subject := noticeHub(), kel2B()[:3]
	n := noticeFor(t, hub, subject, ksnObservedAt)
	body, env, err := DecodeNotice(n)
	if err != nil {
		t.Fatal(err)
	}
	if body.Type != NoticeType || body.Witness != hub.aid || env.SignerAID != hub.aid || env.KeyStateSeq != 2 ||
		env.Alg != aobj.AlgEdDSA || env.PreimageRef != "" {
		t.Fatalf("%+v %+v", body, env)
	}
	held := func(aid string) ([]SignedEvent, bool) { return hub.kel, aid == hub.aid }
	if err := VerifyNotice(n, subject, held, ksnArrival); err != nil {
		t.Fatal(err)
	}
	// A hub Controller signs under its snapshot: the seq in the envelope is its key's.
	c := SuiteController()
	cn, err := SignNotice(c, NoticeBody{AID: subject[0].EventID, Seq: 2, Head: subject[2].EventID, ObservedAt: 1})
	if err != nil {
		t.Fatalf("a hub Controller: %v", err)
	}
	if _, env, err := DecodeNotice(cn); err != nil || env.SignerAID != c.AID() || env.KeyStateSeq != c.CurrentSeq() {
		t.Fatalf("a hub Controller's notice: %+v %v", env, err)
	}
	ok := NoticeBody{AID: subject[0].EventID, Seq: 2, Head: subject[2].EventID, ObservedAt: ksnObservedAt}
	agentKEL := kel2B()[:3]
	for name, c := range map[string]struct {
		s Signer
		b NoticeBody
	}{
		"an agent signs":                {&snapshot{aid: agentKEL[0].EventID, seq: 2, kel: agentKEL, key: vecKeys("KEL-2B")[2]}, ok},
		"another type":                  {hub, func() NoticeBody { b := ok; b.Type = "anet.ksn/2"; return b }()},
		"another witness":               {hub, func() NoticeBody { b := ok; b.Witness = testOtherHub; return b }()},
		"about a string that is no AID": {hub, func() NoticeBody { b := ok; b.AID = "someone"; return b }()},
		"no head":                       {hub, func() NoticeBody { b := ok; b.Head = ""; return b }()},
		"no observed_at":                {hub, func() NoticeBody { b := ok; b.ObservedAt = 0; return b }()},
		"a signer without a key":        {&snapshot{aid: hub.aid, seq: 2, kel: hub.kel}, ok},
		"a signer at another seq":       {&snapshot{aid: hub.aid, seq: 1, kel: hub.kel, key: vecKeys("KEL-2A")[1]}, ok},
		"a signer without a KEL":        {&snapshot{aid: hub.aid, seq: 2, key: vecKeys("KEL-2A")[2]}, ok},
		"no signer":                     {nil, ok},
	} {
		if _, err := SignNotice(c.s, c.b); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// P5: the freshness bounds, to the millisecond.
func TestVerifyNoticeFreshnessBoundaries(t *testing.T) {
	hub, subject := noticeHub(), kel2B()[:3]
	held := func(aid string) ([]SignedEvent, bool) { return hub.kel, aid == hub.aid }
	const obs = ksnObservedAt
	n := noticeFor(t, hub, subject, obs)
	for _, c := range []struct {
		arrival uint64
		want    error
	}{
		{obs, nil},
		{obs + NoticeMaxAge, nil},
		{obs + NoticeMaxAge + 1, ErrNoticeStale},
		{obs - EventClockWindow, nil},
		{obs - EventClockWindow - 1, ErrNoticeStale},
		{math.MaxUint64, ErrNoticeStale},
		{0, ErrNoticeStale},
	} {
		err := VerifyNotice(n, subject, held, c.arrival)
		if (c.want == nil) != (err == nil) || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("arrival %d: %v, want %v", c.arrival, err, c.want)
		}
	}
	if NoticeMaxAge != 6*60*60*1000 {
		t.Fatalf("NoticeMaxAge %d ms, want 6 h", NoticeMaxAge)
	}
	// A notice observed at time 0 is never fresh.
	zero := noticeFor(t, hub, subject, 1)
	if err := VerifyNotice(zero, subject, held, NoticeMaxAge+2); !errors.Is(err, ErrNoticeStale) {
		t.Fatalf("observed at 1: %v", err)
	}
}

// The notice is checked against the KEL it is given, not a later one (D-21): a notice for an older
// tip does not confirm a longer KEL, and the notice for the longer KEL does not confirm the older.
func TestVerifyNoticeIsAboutTheGivenKEL(t *testing.T) {
	hub := noticeHub()
	held := func(aid string) ([]SignedEvent, bool) { return hub.kel, aid == hub.aid }
	b := kel2B()
	w1 := w1KEL()
	w1s := &snapshot{aid: w1[0].EventID, seq: 0, kel: w1, key: testKey("anet-golden/v016/KEL-2B/w1-k0")}
	both := func(aid string) ([]SignedEvent, bool) {
		if aid == w1s.aid {
			return w1, true
		}
		return held(aid)
	}
	old := noticeFor(t, w1s, b[:2], ksnObservedAt)
	if err := VerifyNotice(old, b[:2], both, ksnArrival); err != nil {
		t.Fatalf("the older prefix with its notice: %v", err)
	}
	if err := VerifyNotice(old, b[:3], both, ksnArrival); !errors.Is(err, ErrNoticeMismatch) {
		t.Fatalf("the older notice for the longer KEL: %v", err)
	}
	cur := noticeFor(t, hub, b[:3], ksnObservedAt)
	if err := VerifyNotice(cur, b[:2], both, ksnArrival); !errors.Is(err, ErrNoticeMismatch) {
		t.Fatalf("the newer notice for the older prefix: %v", err)
	}
	// A KEL that does not replay is no notice error.
	bad := clone(b[:3])
	bad[1].Sig = make([]byte, 64)
	err := VerifyNotice(cur, bad, both, ksnArrival)
	for _, e := range []error{ErrNoticeInvalid, ErrNoticeMissing, ErrNoticeMismatch, ErrNoticeUnknownWitness, ErrNoticeStale} {
		if err == nil || errors.Is(err, e) {
			t.Fatalf("a KEL that does not replay: %v", err)
		}
	}
}

func TestDecodeNotice(t *testing.T) {
	hub, subject := noticeHub(), kel2B()[:3]
	n := noticeFor(t, hub, subject, ksnObservedAt)
	var w NoticeWire
	if err := coredet.UnmarshalStrict(n, &w); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"empty":             nil,
		"null":              {0xf6},
		"an empty map":      {0xa0},
		"truncated":         n[:len(n)-1],
		"one byte more":     append(append([]byte(nil), n...), 0),
		"the body alone":    w.Body,
		"a preimage ref":    ksnMarshal(t, NoticeWire{Body: w.Body, Env: aobj.Envelope{SignerAID: w.Env.SignerAID, KeyStateSeq: 2, Alg: aobj.AlgEdDSA, Sig: w.Env.Sig, PreimageRef: "r"}}),
		"a body of null":    ksnMarshal(t, map[uint64]any{1: nil, 2: map[uint64]any{1: w.Env.SignerAID, 2: 2, 3: -8, 4: w.Env.Sig}}),
		"env key 2 missing": ksnMarshal(t, map[uint64]any{1: w.Body, 2: map[uint64]any{1: w.Env.SignerAID, 3: -8, 4: w.Env.Sig}}),
		"body key 4 null": ksnSigned(t, ksnMarshal(t, map[uint64]any{0: NoticeType, 1: subject[0].EventID, 2: 2, 3: subject[2].EventID,
			4: nil, 5: hub.aid}), hub.aid, 2, hub.key),
	} {
		if _, _, err := DecodeNotice(b); !errors.Is(err, ErrNoticeInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// FuzzVerifyNotice: no input panics VerifyNotice, and what it accepts is a notice in CoreDet form
// whose body states the tip of the subject KEL, signed by its witness hub, fresh at arrival.
func FuzzVerifyNotice(f *testing.F) {
	hub, subject := noticeHub(), kel2B()[:3]
	full := kel2A()
	n := noticeFor(f, hub, subject, ksnObservedAt)
	f.Add(n, ksnArrival, false)
	f.Add(n, hubDipTS, true)
	f.Add([]byte{0xa0}, uint64(0), false)
	if b, err := os.ReadFile(filepath.Join("testdata", ksnFile)); err == nil {
		var v ksnVector
		if json.Unmarshal(b, &v) == nil {
			for _, c := range v.Cases {
				if nb, err := hex.DecodeString(c.Notice); err == nil {
					f.Add(nb, c.Arrival, false)
				}
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte, arrival uint64, retired bool) {
		wkel := hub.kel
		if retired {
			wkel = full
		}
		held := func(aid string) ([]SignedEvent, bool) { return wkel, aid == hub.aid }
		err := VerifyNotice(b, subject, held, arrival)
		body, env, derr := DecodeNotice(b)
		if derr != nil {
			if err == nil || !errors.Is(err, ErrNoticeInvalid) {
				t.Fatalf("DecodeNotice refuses (%v), VerifyNotice says %v", derr, err)
			}
			return
		}
		if err != nil {
			return
		}
		pre, merr := coredet.Marshal(body)
		back, werr := coredet.Marshal(NoticeWire{Body: pre, Env: env})
		tip := subject[2]
		switch {
		case merr != nil || werr != nil || !bytes.Equal(back, b):
			t.Fatal("accepted a notice that is not in CoreDet form")
		case body.AID != subject[0].EventID || body.Seq != 2 || body.Head != tip.EventID || body.Witness != hub.aid || env.SignerAID != hub.aid:
			t.Fatalf("accepted a notice about another tip or from another witness: %+v %+v", body, env)
		case env.KeyStateSeq != 2 || !ed25519.Verify(pubOf(hub.key), pre, env.Sig):
			t.Fatalf("accepted a notice the witness did not sign at its key state 2: %+v", env)
		case body.ObservedAt > arrival && body.ObservedAt-arrival > EventClockWindow,
			arrival > body.ObservedAt && arrival-body.ObservedAt > NoticeMaxAge:
			t.Fatalf("accepted a stale notice: observed %d, arrival %d", body.ObservedAt, arrival)
		case retired && arrival > hubDipTS:
			t.Fatalf("accepted a notice under a key state the dip retired, arriving at %d", arrival)
		}
	})
}

// ---- D-44: MergedEmergency -----------------------------------------------------------------------

func TestMergedEmergency(t *testing.T) {
	a := kel2A() // rot 1 planned, rot 2 emergency, dip 3
	for _, c := range []struct {
		name      string
		old, next []SignedEvent
		want      bool
	}{
		{"the planned rot 1 merged", a[:1], a[:2], false},
		{"the emergency rot 2 merged", a[:2], a[:3], true},
		{"both rots merged at once", a[:1], a[:3], true},
		{"the whole KEL learnt at once", nil, a, true},
		{"the dip merged", a[:3], a, false},
		{"nothing new", a[:3], a[:3], false},
		{"a shorter KEL", a, a[:2], false},
		{"an agent's planned rots", kel2B()[:1], kel2B()[:3], false},
	} {
		if got := MergedEmergency(c.old, c.next); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
