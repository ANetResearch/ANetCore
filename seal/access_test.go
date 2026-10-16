package seal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"math"
	"reflect"
	"testing"
)

const fileAccess1 = "testdata/vec-access-1.json"

// vecCapBody is a CapBody as the vectors write it.
type vecCapBody struct {
	T      string   `json:"t"`
	Owner  string   `json:"owner"`
	Epoch  uint64   `json:"epoch"`
	CapID  hexBytes `json:"cap_id"`
	Class  uint64   `json:"class"`
	CapExp uint64   `json:"cap_exp"`
	Holder hexBytes `json:"holder"`
}

func (v vecCapBody) body() CapBody {
	return CapBody{Type: v.T, Owner: v.Owner, Epoch: v.Epoch, CapID: v.CapID, Class: v.Class, CapExp: v.CapExp, Holder: v.Holder}
}

type vecKey struct {
	SeedRole string   `json:"seed_role"`
	Epoch    uint64   `json:"epoch"`
	Pub      hexBytes `json:"pub"`
}

// key derives the Ed25519 key of k's seed role in vector vid and checks it against the file.
func (k vecKey) key(t *testing.T, vid string) ed25519.PrivateKey {
	t.Helper()
	sk := ed25519.NewKeyFromSeed(goldenSeed(vid, k.SeedRole))
	if !bytes.Equal(sk.Public().(ed25519.PublicKey), k.Pub) {
		t.Fatalf("%s: the key of seed %q is not the file's", vid, k.SeedRole)
	}
	return sk
}

type vecAccess1 struct {
	ID          string     `json:"id"`
	Now         uint64     `json:"now"`
	Owner       string     `json:"owner"`
	Mbox        vecKey     `json:"mbox"`
	Holder      vecKey     `json:"holder"`
	CapBody     vecCapBody `json:"cap_body"`
	CapBodyCBOR hexBytes   `json:"cap_body_cbor"`
	CapSig      hexBytes   `json:"cap_sig"`
	Cap         hexBytes   `json:"cap"`
	Sealed      hexBytes   `json:"sealed"`
	EnvDigest   hexBytes   `json:"env_digest"`
	ProofInput  hexBytes   `json:"proof_input"`
	Proof       hexBytes   `json:"proof"`
	Access      hexBytes   `json:"access"`
	Envelope    hexBytes   `json:"envelope"`
	Cases       []struct {
		Name      string   `json:"name"`
		Envelope  hexBytes `json:"envelope"`
		MboxEpoch uint64   `json:"mbox_epoch"`
		MboxPub   hexBytes `json:"mbox_pub"`
		Now       uint64   `json:"now"`
		Step      string   `json:"step"`
	} `json:"cases"`
}

// wantStep fails unless err is access-invalid with Detail step ("" = no error).
func wantStep(t *testing.T, err error, step string) {
	t.Helper()
	if step == "" {
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		return
	}
	var se *Error
	if !errors.As(err, &se) || se.Reason != ReasonAccessInvalid || se.Detail != step {
		t.Fatalf("got %v, want access-invalid at step %q", err, step)
	}
	if !IsPermanent(err) {
		t.Fatal("an access-invalid failure is not permanent")
	}
}

// ACCESS-1 (core §5.2): Go reproduces the capability, the proof and the access from the seeds
// byte for byte, and VerifyAccess, called the way the hub calls it (the access of outer key 7,
// env_digest of the envelope, the owner's mailbox key, outer to), fails each case at its step.
func TestACCESS_1(t *testing.T) {
	var v vecAccess1
	readVector(t, fileAccess1, &v)
	if v.ID != "ACCESS-1" {
		t.Fatalf("vector id %q", v.ID)
	}
	mbox, holder := v.Mbox.key(t, v.ID), v.Holder.key(t, v.ID)
	body := v.CapBody.body()
	if !bytes.Equal(body.CapID, goldenSeed(v.ID, "cap-id")[:CapIDLen]) || body.Owner != v.Owner ||
		!bytes.Equal(body.Holder, v.Holder.Pub) || body.Type != CapType {
		t.Fatal("the file's CapBody is not the one its seeds give")
	}

	t.Run("capability", func(t *testing.T) {
		b, err := body.Marshal()
		if err != nil || !bytes.Equal(b, v.CapBodyCBOR) {
			t.Fatalf("CapBody encodes to %x, file %x (%v)", b, v.CapBodyCBOR, err)
		}
		got, err := UnmarshalCapBody(v.CapBodyCBOR)
		if err != nil || !reflect.DeepEqual(*got, body) {
			t.Fatalf("decoded %+v (%v)", got, err)
		}
		c, err := SignCap(mbox, &body)
		if err != nil || !bytes.Equal(c.Body, v.CapBodyCBOR) || !bytes.Equal(c.Sig, v.CapSig) {
			t.Fatalf("SignCap: %+v (%v)", c, err)
		}
		cb, err := c.Marshal()
		if err != nil || !bytes.Equal(cb, v.Cap) {
			t.Fatalf("Cap encodes to %x, file %x (%v)", cb, v.Cap, err)
		}
		if uc, err := UnmarshalCap(v.Cap); err != nil || !reflect.DeepEqual(uc, c) {
			t.Fatalf("UnmarshalCap: %+v (%v)", uc, err)
		}
	})
	t.Run("proof and access", func(t *testing.T) {
		d, err := EnvDigest(v.Sealed)
		if err != nil || !bytes.Equal(d[:], v.EnvDigest) {
			t.Fatalf("env_digest %x, file %x (%v)", d, v.EnvDigest, err)
		}
		if !bytes.Equal(accessInput(body.CapID, d), v.ProofInput) {
			t.Fatal("the proof input differs from the file (L5)")
		}
		proof := SignAccess(holder, body.CapID, d)
		if !bytes.Equal(proof, v.Proof) {
			t.Fatalf("proof %x, file %x", proof, v.Proof)
		}
		a := &Access{Kind: AccessKindCap, Cap: &Cap{Body: v.CapBodyCBOR, Sig: v.CapSig}, Proof: proof}
		ab, err := encodeAccess(a)
		if err != nil || !bytes.Equal(ab, v.Access) {
			t.Fatalf("access encodes to %x, file %x (%v)", ab, v.Access, err)
		}
		env, err := SetAccess(v.Sealed, a)
		if err != nil || !bytes.Equal(env, v.Envelope) {
			t.Fatalf("SetAccess(sealed, access) is not the file's envelope (%v)", err)
		}
		o, err := ParseOuter(v.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyAccess(o.Access, d, Mbox{Epoch: v.Mbox.Epoch, Pub: v.Mbox.Pub}, o.To, v.Now); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("cases", func(t *testing.T) {
		seen := map[string]bool{}
		for _, c := range v.Cases {
			seen[c.Step] = true
			t.Run(c.Name, func(t *testing.T) {
				o, err := ParseOuter(c.Envelope)
				if err != nil {
					t.Fatalf("ParseOuter: %v", err)
				}
				d, err := EnvDigest(c.Envelope)
				if err != nil {
					t.Fatal(err)
				}
				wantStep(t, VerifyAccess(o.Access, d, Mbox{Epoch: c.MboxEpoch, Pub: c.MboxPub}, o.To, c.Now), c.Step)
			})
		}
		for _, s := range []string{"", "decode", "type", "owner", "epoch", "sig", "exp", "proof"} {
			if !seen[s] {
				t.Errorf("no case for step %q", s)
			}
		}
	})
}

// accessScene is one VerifyAccess call built from parts each test can break.
type accessScene struct {
	body      CapBody
	longEpoch bool               // encode epoch in a non-shortest form (not CoreDet)
	signer    ed25519.PrivateKey // the key Cap.sig is made with
	holder    ed25519.PrivateKey // the key the proof is made with
	env       [32]byte           // the env_digest the proof is made over
	digest    [32]byte           // the env_digest the verifier computes
	mbox      Mbox
	owner     string
	now       uint64
}

func newAccessScene() *accessScene {
	k := func(role string) ed25519.PrivateKey {
		return ed25519.NewKeyFromSeed(goldenSeed("ACCESS-1", "test/"+role))
	}
	mbox, holder := k("mbox"), k("holder")
	d := [32]byte{1, 2, 3}
	return &accessScene{
		body: CapBody{Type: CapType, Owner: "bafyowner", Epoch: 3, CapID: bytes.Repeat([]byte{7}, CapIDLen),
			Class: CapClassStranger, CapExp: t0 + dayMS, Holder: holder.Public().(ed25519.PublicKey)},
		signer: mbox, holder: holder, env: d, digest: d,
		mbox:  Mbox{Epoch: 3, Pub: mbox.Public().(ed25519.PublicKey)},
		owner: "bafyowner", now: t0,
	}
}

func (s *accessScene) access(t *testing.T) *Access {
	t.Helper()
	b, err := s.body.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if s.longEpoch {
		m, err := decodeFields(b)
		if err != nil {
			t.Fatal(err)
		}
		var e uint64
		if e, err = rawUint(m, 2); err != nil || e > 0xff {
			t.Fatalf("epoch %d (%v)", e, err)
		}
		m[2] = []byte{0x19, 0, byte(e)} // uint16 form of a value below 256
		b = mustMarshalFields(t, m)
	}
	return &Access{Kind: AccessKindCap, Cap: &Cap{Body: b, Sig: ed25519.Sign(s.signer, b)},
		Proof: SignAccess(s.holder, s.body.CapID, s.env)}
}

func (s *accessScene) verify(t *testing.T) error {
	t.Helper()
	return VerifyAccess(s.access(t), s.digest, s.mbox, s.owner, s.now)
}

// SSR-W23, CORE-K2: each step, broken alone, fails with access-invalid and its own name as
// Detail; broken together with every later step, it is still the one reported, so the steps run
// in the fixed order.
func TestVerifyAccessOrder(t *testing.T) {
	other := ed25519.NewKeyFromSeed(goldenSeed("ACCESS-1", "test/other"))
	steps := []struct {
		name   string
		break_ func(s *accessScene)
	}{
		{"decode", func(s *accessScene) { s.longEpoch = true }},
		{"type", func(s *accessScene) { s.body.Type = "anet.cap/2" }},
		{"owner", func(s *accessScene) { s.owner = "bafysomeoneelse" }},
		{"epoch", func(s *accessScene) { s.mbox.Epoch = 4 }},
		{"sig", func(s *accessScene) { s.signer = other }},
		{"exp", func(s *accessScene) { s.body.CapExp = s.now - CapExpGraceMS - 1 }},
		{"proof", func(s *accessScene) { s.digest[0] ^= 1 }},
	}
	if err := newAccessScene().verify(t); err != nil {
		t.Fatalf("the unbroken scene is refused: %v", err)
	}
	for i, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			alone := newAccessScene()
			st.break_(alone)
			wantStep(t, alone.verify(t), st.name)
			all := newAccessScene()
			for j := len(steps) - 1; j >= i; j-- {
				steps[j].break_(all)
			}
			wantStep(t, all.verify(t), st.name)
		})
	}
	// Other ways each step fails.
	for name, c := range map[string]struct {
		step   string
		break_ func(s *accessScene)
	}{
		"class 0":                    {"decode", func(s *accessScene) { s.body.Class = 0 }},
		"class 3":                    {"decode", func(s *accessScene) { s.body.Class = 3 }},
		"empty owner":                {"owner", func(s *accessScene) { s.owner, s.body.Owner = "", "" }},
		"mailbox epoch 0":            {"epoch", func(s *accessScene) { s.mbox.Epoch, s.body.Epoch = 0, 0 }},
		"mailbox key of 31 bytes":    {"sig", func(s *accessScene) { s.mbox.Pub = s.mbox.Pub[:31] }},
		"no mailbox key":             {"sig", func(s *accessScene) { s.mbox.Pub = nil }},
		"too far ahead":              {"exp", func(s *accessScene) { s.body.CapExp = s.now + CapExpMaxAheadMS + 1 }},
		"proof by another holder":    {"proof", func(s *accessScene) { s.holder = other }},
		"proof for another envelope": {"proof", func(s *accessScene) { s.env[31] ^= 1 }},
	} {
		t.Run(name, func(t *testing.T) {
			s := newAccessScene()
			c.break_(s)
			wantStep(t, s.verify(t), c.step)
		})
	}
	// The edges of the window are inside it.
	for _, exp := range []uint64{t0 - CapExpGraceMS, t0 + CapExpMaxAheadMS} {
		s := newAccessScene()
		s.body.CapExp = exp
		if err := s.verify(t); err != nil {
			t.Fatalf("cap_exp %d at %d: %v", exp, s.now, err)
		}
	}
}

// An access that is not a well-formed kind-1 access fails before the first step, as ParseOuter
// reports it ("parse"). VerifyAccess does not trust its caller to have run ParseOuter.
func TestVerifyAccessParse(t *testing.T) {
	s := newAccessScene()
	good := s.access(t)
	for name, a := range map[string]*Access{
		"nil":           nil,
		"kind 0":        {Kind: AccessKindSession},
		"kind 2":        {Kind: 2, Cap: good.Cap, Proof: good.Proof},
		"no cap":        {Kind: AccessKindCap, Proof: good.Proof},
		"short cap sig": {Kind: AccessKindCap, Cap: &Cap{Body: good.Cap.Body, Sig: good.Cap.Sig[:63]}, Proof: good.Proof},
		"short proof":   {Kind: AccessKindCap, Cap: good.Cap, Proof: good.Proof[:63]},
		"no proof":      {Kind: AccessKindCap, Cap: good.Cap},
	} {
		t.Run(name, func(t *testing.T) {
			wantStep(t, VerifyAccess(a, s.digest, s.mbox, s.owner, s.now), "parse")
		})
	}
}

// The strict decode of Cap.body (SSR-W3, CORE-E2, CORE-E3): only the CoreDet encoding of a
// CapBody with exactly its keys, each of its type and size.
func TestUnmarshalCapBodyStrict(t *testing.T) {
	s := newAccessScene()
	valid, err := s.body.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := UnmarshalCapBody(valid); err != nil || !reflect.DeepEqual(*got, s.body) {
		t.Fatalf("valid body: %+v %v", got, err)
	}
	base, err := decodeFields(valid)
	if err != nil {
		t.Fatal(err)
	}
	with := func(k uint64, v []byte) []byte {
		m := fieldMap{}
		for kk, vv := range base {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return mustMarshalFields(t, m)
	}
	for name, b := range map[string][]byte{
		"not a map":            {0x80},
		"empty":                nil,
		"trailing byte":        append(append([]byte(nil), valid...), 0),
		"key 7":                with(7, enc(t, "x")),
		"key 64":               with(64, enc(t, "x")),
		"key 0 missing":        with(0, nil),
		"key 6 missing":        with(6, nil),
		"type as bytes":        with(0, enc(t, []byte(CapType))),
		"owner as uint":        with(1, enc(t, uint64(1))),
		"epoch negative":       with(2, []byte{0x20}),
		"epoch as text":        with(2, enc(t, "3")),
		"cap_id of 15 bytes":   with(3, enc(t, make([]byte, 15))),
		"cap_id of 17 bytes":   with(3, enc(t, make([]byte, 17))),
		"class null":           with(4, []byte{0xf6}),
		"cap_exp as float":     with(5, []byte{0xf9, 0x3c, 0x00}),
		"holder of 31 bytes":   with(6, enc(t, make([]byte, 31))),
		"holder as text":       with(6, enc(t, string(make([]byte, 32)))),
		"epoch in a long form": with(2, []byte{0x18, 0x03}),
		"keys out of order":    inOrder(base, 1, 0, 2, 3, 4, 5, 6),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := UnmarshalCapBody(b)
			wantStep(t, err, "decode")
		})
	}
}

// UnmarshalCap and Cap.Marshal: the structure of the wire form, as outer key 7 and a grant carry it.
func TestCapWireForm(t *testing.T) {
	c := &Cap{Body: []byte("body"), Sig: bytes.Repeat([]byte{1}, SigLen)}
	b, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := UnmarshalCap(b); err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	for name, bad := range map[string]any{
		"short sig": map[uint64]any{1: []byte("b"), 2: make([]byte, 63)},
		"body text": map[uint64]any{1: "b", 2: make([]byte, 64)},
		"no sig":    map[uint64]any{1: []byte("b")},
		"key 0":     map[uint64]any{0: "x", 1: []byte("b"), 2: make([]byte, 64)},
		"key 3":     map[uint64]any{1: []byte("b"), 2: make([]byte, 64), 3: "x"},
		"an array":  []any{[]byte("b"), make([]byte, 64)},
		"null":      nil,
	} {
		_, err := UnmarshalCap(enc(t, bad))
		var se *Error
		if !errors.As(err, &se) || se.Reason != ReasonAccessInvalid || se.Detail != "parse" {
			t.Errorf("%s: %v, want access-invalid parse", name, err)
		}
	}
	for name, bad := range map[string]*Cap{"nil": nil, "short sig": {Body: []byte("b"), Sig: make([]byte, 10)}} {
		if _, err := bad.Marshal(); ReasonOf(err) != ReasonInvalidInput {
			t.Errorf("%s: %v, want invalid-input", name, err)
		}
	}
}

// SignCap signs only what every verifier accepts on the body alone, and fills in the type tag.
func TestSignCap(t *testing.T) {
	s := newAccessScene()
	b := s.body
	b.Type = ""
	c, err := SignCap(s.signer, &b)
	if err != nil {
		t.Fatal(err)
	}
	if b.Type != "" {
		t.Fatal("SignCap changed its argument")
	}
	got, err := UnmarshalCapBody(c.Body)
	if err != nil || got.Type != CapType || !ed25519.Verify(s.mbox.Pub, c.Body, c.Sig) {
		t.Fatalf("signed cap: %+v %v", got, err)
	}
	if err := VerifyAccess(&Access{Kind: AccessKindCap, Cap: c, Proof: SignAccess(s.holder, b.CapID, s.digest)},
		s.digest, s.mbox, s.owner, s.now); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*CapBody){
		"type anet.cap/2":   func(b *CapBody) { b.Type = "anet.cap/2" },
		"empty owner":       func(b *CapBody) { b.Owner = "" },
		"owner with U+0000": func(b *CapBody) { b.Owner = "bafy\x00x" },
		"epoch 0":           func(b *CapBody) { b.Epoch = 0 },
		"cap_id 15 bytes":   func(b *CapBody) { b.CapID = b.CapID[:15] },
		"class 0":           func(b *CapBody) { b.Class = 0 },
		"class 3":           func(b *CapBody) { b.Class = 3 },
		"cap_exp 0":         func(b *CapBody) { b.CapExp = 0 },
		"holder 31 bytes":   func(b *CapBody) { b.Holder = b.Holder[:31] },
	} {
		b := s.body
		mod(&b)
		if _, err := SignCap(s.signer, &b); ReasonOf(err) != ReasonInvalidInput {
			t.Errorf("%s: %v, want invalid-input", name, err)
		}
	}
	if _, err := SignCap(s.signer, nil); ReasonOf(err) != ReasonInvalidInput {
		t.Errorf("nil body: %v", err)
	}
	if _, err := SignCap(s.signer[:32], &s.body); ReasonOf(err) != ReasonInvalidInput {
		t.Errorf("a seed instead of a key: %v", err)
	}
}

// SignAccess makes the L5 proof, and makes none from a malformed key or id; SetAccess then
// refuses the access instead of sending it.
func TestSignAccess(t *testing.T) {
	s := newAccessScene()
	proof := SignAccess(s.holder, s.body.CapID, s.env)
	in := append(append([]byte("anet-access/v2\x00"), s.body.CapID...), s.env[:]...)
	if !ed25519.Verify(s.body.Holder, in, proof) {
		t.Fatal("the proof is not the holder's signature over label 0x00 cap_id env_digest")
	}
	for name, p := range map[string][]byte{
		"seed for a key":  SignAccess(s.holder.Seed(), s.body.CapID, s.env),
		"nil key":         SignAccess(nil, s.body.CapID, s.env),
		"cap_id 15 bytes": SignAccess(s.holder, s.body.CapID[:15], s.env),
		"cap_id 17 bytes": SignAccess(s.holder, append(append([]byte(nil), s.body.CapID...), 0), s.env),
	} {
		if p != nil {
			t.Errorf("%s: a proof", name)
		}
		a := s.access(t)
		a.Proof = p
		if _, err := encodeAccess(a); err == nil {
			t.Errorf("%s: SetAccess would take an access without a proof", name)
		}
	}
}

// The window of cap_exp at the ends of the clock.
func TestCapExpWindow(t *testing.T) {
	for _, c := range []struct {
		exp, now uint64
		ok       bool
	}{
		{0, 0, true},
		{0, CapExpGraceMS, true},
		{0, CapExpGraceMS + 1, false},
		{CapExpMaxAheadMS, 0, true},
		{CapExpMaxAheadMS + 1, 0, false},
		{math.MaxUint64, math.MaxUint64, true},
		{math.MaxUint64, math.MaxUint64 - CapExpMaxAheadMS, true},
		{math.MaxUint64, math.MaxUint64 - CapExpMaxAheadMS - 1, false},
		{math.MaxUint64 - CapExpGraceMS, math.MaxUint64, true},
		{math.MaxUint64 - CapExpGraceMS - 1, math.MaxUint64, false},
	} {
		if got := capExpInWindow(c.exp, c.now); got != c.ok {
			t.Errorf("cap_exp %d at %d: %v, want %v", c.exp, c.now, got, c.ok)
		}
	}
}

// inOrder encodes the map m with its keys (all below 24) written in the given order: a map
// CoreDet would write otherwise, for a not-canonical negative.
func inOrder(m fieldMap, keys ...uint64) []byte {
	out := []byte{0xa0 | byte(len(keys))}
	for _, k := range keys {
		out = append(out, byte(k))
		out = append(out, m[k]...)
	}
	return out
}
