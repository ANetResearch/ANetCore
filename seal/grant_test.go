package seal

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"
)

const fileGrant1 = "testdata/vec-grant-1.json"

type vecGrant1 struct {
	ID     string `json:"id"`
	Now    uint64 `json:"now"`
	Issuer string `json:"issuer"`
	IX     string `json:"ix"`
	Mbox   vecKey `json:"mbox"`
	Grants []struct {
		Name        string     `json:"name"`
		Role        string     `json:"role"`
		CapBody     vecCapBody `json:"cap_body"`
		CapBodyCBOR hexBytes   `json:"cap_body_cbor"`
		CapSig      hexBytes   `json:"cap_sig"`
		HolderSeed  hexBytes   `json:"holder_seed"`
		Home        string     `json:"home"`
		IX          *string    `json:"ix"`
		P2P         *string    `json:"p2p"`
		Pay         *bool      `json:"pay"`
		Grant       hexBytes   `json:"grant"`
	} `json:"grants"`
	Cases []struct {
		Name      string   `json:"name"`
		Grant     hexBytes `json:"grant"`
		From      string   `json:"from"`
		IX        string   `json:"ix"`
		KeysAID   string   `json:"keys_aid"`
		MboxEpoch uint64   `json:"mbox_epoch"`
		MboxPub   hexBytes `json:"mbox_pub"`
		Now       uint64   `json:"now"`
		Step      string   `json:"step"`
	} `json:"cases"`
}

// GRANT-1 (core §5.2): Go reproduces each valid grant from its seeds byte for byte and CheckGrant
// keeps it; each case fails at its step, in a message from "from" in interaction "ix", checked
// against the key set of "keys_aid" with the given mailbox key.
func TestGRANT_1(t *testing.T) {
	var v vecGrant1
	readVector(t, fileGrant1, &v)
	if v.ID != "GRANT-1" {
		t.Fatalf("vector id %q", v.ID)
	}
	mbox := v.Mbox.key(t, v.ID)
	keys := &EncKeySet{AID: v.Issuer, Mbox: Mbox{Epoch: v.Mbox.Epoch, Pub: v.Mbox.Pub}}
	fields := map[string]bool{}
	for _, gv := range v.Grants {
		t.Run(gv.Name, func(t *testing.T) {
			body := gv.CapBody.body()
			if !bytes.Equal(gv.HolderSeed, goldenSeed(v.ID, "holder/"+gv.Role)) ||
				!bytes.Equal(body.CapID, goldenSeed(v.ID, "cap-id/"+gv.Role)[:CapIDLen]) ||
				!bytes.Equal(body.Holder, ed25519.NewKeyFromSeed(gv.HolderSeed).Public().(ed25519.PublicKey)) {
				t.Fatal("the file's grant is not the one its seeds give")
			}
			c, err := SignCap(mbox, &body)
			if err != nil || !bytes.Equal(c.Body, gv.CapBodyCBOR) || !bytes.Equal(c.Sig, gv.CapSig) {
				t.Fatalf("SignCap: %x %x (%v)", c.Body, c.Sig, err)
			}
			g := &Grant{Cap: *c, HolderSeed: gv.HolderSeed, Home: gv.Home, IX: gv.IX, P2P: gv.P2P, Pay: gv.Pay}
			b, err := g.Marshal()
			if err != nil || !bytes.Equal(b, gv.Grant) {
				t.Fatalf("Grant encodes to %x, file %x (%v)", b, gv.Grant, err)
			}
			if u, err := UnmarshalGrant(gv.Grant); err != nil || !reflect.DeepEqual(u, g) {
				t.Fatalf("UnmarshalGrant: %+v (%v)", u, err)
			}
			kept, kb, err := CheckGrant(&SealedInner{From: v.Issuer, IX: v.IX, Grant: []byte(gv.Grant)}, keys, v.Now)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(kept, g) || !reflect.DeepEqual(*kb, body) {
				t.Fatalf("CheckGrant kept %+v %+v", kept, kb)
			}
			for name, on := range map[string]bool{"ix": g.IX != nil, "p2p": g.P2P != nil, "pay": g.Pay != nil} {
				if on {
					fields[name] = true
				}
			}
		})
	}
	for _, f := range []string{"ix", "p2p", "pay"} {
		if !fields[f] {
			t.Errorf("no valid grant carries %s", f)
		}
	}
	seen := map[string]bool{}
	for _, c := range v.Cases {
		seen[c.Step] = true
		t.Run(c.Name, func(t *testing.T) {
			ks := &EncKeySet{AID: c.KeysAID, Mbox: Mbox{Epoch: c.MboxEpoch, Pub: c.MboxPub}}
			g, body, err := CheckGrant(&SealedInner{From: c.From, IX: c.IX, Grant: []byte(c.Grant)}, ks, c.Now)
			wantStep(t, err, c.Step)
			if (err == nil) != (g != nil && body != nil) {
				t.Fatalf("grant %v and body %v with error %v", g != nil, body != nil, err)
			}
		})
	}
	for _, s := range []string{"", "decode", "body", "type", "owner", "keys", "epoch", "sig", "holder", "class", "exp", "ix", "p2p", "pay"} {
		if !seen[s] {
			t.Errorf("no case for step %q", s)
		}
	}
}

// grantScene is one CheckGrant call built from parts each test can break.
type grantScene struct {
	body       CapBody
	longEpoch  bool               // encode Cap.body's epoch in a non-shortest form
	signer     ed25519.PrivateKey // the key Cap.sig is made with
	seed       []byte             // the grant's holder seed
	home       string
	ix, p2p    *string
	pay        *bool
	extraKey   bool // add the unregistered key 7 to the grant
	from, inIX string
	keys       EncKeySet
	now        uint64
}

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }

func newGrantScene() *grantScene {
	k := func(role string) ed25519.PrivateKey {
		return ed25519.NewKeyFromSeed(goldenSeed("GRANT-1", "test/"+role))
	}
	mbox, holder := k("mbox"), k("holder")
	return &grantScene{
		body: CapBody{Type: CapType, Owner: "bafyissuer", Epoch: 5, CapID: bytes.Repeat([]byte{9}, CapIDLen),
			Class: CapClassContact, CapExp: t0 + 7*dayMS, Holder: holder.Public().(ed25519.PublicKey)},
		signer: mbox, seed: holder.Seed(), home: "bafyhome",
		from: "bafyissuer", inIX: "ix-1",
		keys: EncKeySet{AID: "bafyissuer", Mbox: Mbox{Epoch: 5, Pub: mbox.Public().(ed25519.PublicKey)}},
		now:  t0,
	}
}

func (s *grantScene) grantBytes(t *testing.T) []byte {
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
		e, err := rawUint(m, 2)
		if err != nil || e > 0xff {
			t.Fatalf("epoch %d (%v)", e, err)
		}
		m[2] = []byte{0x19, 0, byte(e)}
		b = mustMarshalFields(t, m)
	}
	g := Grant{Cap: Cap{Body: b, Sig: ed25519.Sign(s.signer, b)}, HolderSeed: s.seed, Home: s.home, IX: s.ix, P2P: s.p2p, Pay: s.pay}
	out := enc(t, g)
	if s.extraKey {
		m, err := decodeFields(out)
		if err != nil {
			t.Fatal(err)
		}
		m[7] = enc(t, "x")
		out = mustMarshalFields(t, m)
	}
	return out
}

func (s *grantScene) check(t *testing.T) error {
	t.Helper()
	keys := s.keys
	_, _, err := CheckGrant(&SealedInner{From: s.from, IX: s.inIX, Grant: s.grantBytes(t)}, &keys, s.now)
	return err
}

// SSR-W7: each check, failed alone, fails with access-invalid and its own name as Detail; failed
// together with every later check, it is still the one reported, so the checks run in order.
// The breakers are applied from the last to the first, so an earlier one wins where two touch
// the same part.
func TestCheckGrantOrder(t *testing.T) {
	other := ed25519.NewKeyFromSeed(goldenSeed("GRANT-1", "test/other"))
	steps := []struct {
		name   string
		break_ func(s *grantScene)
	}{
		{"decode", func(s *grantScene) { s.extraKey = true }},
		{"body", func(s *grantScene) { s.longEpoch = true }},
		{"type", func(s *grantScene) { s.body.Type = "anet.cap/2" }},
		{"owner", func(s *grantScene) { s.body.Owner = "bafysomeoneelse" }},
		{"keys", func(s *grantScene) { s.keys.AID = "bafysomeoneelse" }},
		{"epoch", func(s *grantScene) { s.keys.Mbox.Epoch = 6 }},
		{"sig", func(s *grantScene) { s.signer = other }},
		{"holder", func(s *grantScene) { s.seed = other.Seed() }},
		{"class", func(s *grantScene) { s.body.Class = 3 }},
		{"exp", func(s *grantScene) { s.body.CapExp = s.now - CapExpGraceMS - 1 }},
		{"ix", func(s *grantScene) { s.ix = strp("ix-other") }},
		{"p2p", func(s *grantScene) { s.p2p, s.body.Class = strp("192.0.2.1:1"), CapClassStranger }},
		{"pay", func(s *grantScene) { s.pay, s.ix = boolp(true), strp(s.inIX) }},
	}
	if err := newGrantScene().check(t); err != nil {
		t.Fatalf("the unbroken scene is refused: %v", err)
	}
	for i, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			alone := newGrantScene()
			st.break_(alone)
			wantStep(t, alone.check(t), st.name)
			all := newGrantScene()
			for j := len(steps) - 1; j >= i; j-- {
				steps[j].break_(all)
			}
			wantStep(t, all.check(t), st.name)
		})
	}
	// Other ways each check fails, and what passes.
	for name, c := range map[string]struct {
		step   string
		break_ func(s *grantScene)
	}{
		"no key set":                      {"keys", nil},
		"class 0":                         {"class", func(s *grantScene) { s.body.Class = 0 }},
		"too far ahead":                   {"exp", func(s *grantScene) { s.body.CapExp = s.now + CapExpMaxAheadMS + 1 }},
		"key set with mailbox epoch 0":    {"epoch", func(s *grantScene) { s.keys.Mbox.Epoch, s.body.Epoch = 0, 0 }},
		"mailbox key of 31 bytes":         {"sig", func(s *grantScene) { s.keys.Mbox.Pub = s.keys.Mbox.Pub[:31] }},
		"p2p in a one-shot grant":         {"p2p", func(s *grantScene) { s.p2p, s.ix = strp("192.0.2.1:1"), strp(s.inIX) }},
		"pay false in a one-shot grant":   {"pay", func(s *grantScene) { s.pay, s.ix = boolp(false), strp(s.inIX) }},
		"empty home":                      {"decode", func(s *grantScene) { s.home = "" }},
		"home with U+0000":                {"decode", func(s *grantScene) { s.home = "bafy\x00home" }},
		"holder seed of 31 bytes":         {"decode", func(s *grantScene) { s.seed = s.seed[:31] }},
		"one-shot for this interaction":   {"", func(s *grantScene) { s.ix = strp(s.inIX) }},
		"one-shot for an empty ix":        {"", func(s *grantScene) { s.ix, s.inIX = strp(""), "" }},
		"contact peer with p2p and pay":   {"", func(s *grantScene) { s.p2p, s.pay = strp("192.0.2.1:1"), boolp(true) }},
		"stranger peer with pay false":    {"", func(s *grantScene) { s.body.Class, s.pay = CapClassStranger, boolp(false) }},
		"cap_exp at the lower edge":       {"", func(s *grantScene) { s.body.CapExp = s.now - CapExpGraceMS }},
		"cap_exp at the upper edge":       {"", func(s *grantScene) { s.body.CapExp = s.now + CapExpMaxAheadMS }},
		"ix of the grant, none in inner":  {"ix", func(s *grantScene) { s.ix, s.inIX = strp("ix-1"), "" }},
		"empty ix in the grant, inner ix": {"ix", func(s *grantScene) { s.ix = strp("") }},
	} {
		t.Run(name, func(t *testing.T) {
			s := newGrantScene()
			if c.break_ == nil { // no key set at all
				_, _, err := CheckGrant(&SealedInner{From: s.from, IX: s.inIX, Grant: s.grantBytes(t)}, nil, s.now)
				wantStep(t, err, c.step)
				return
			}
			c.break_(s)
			wantStep(t, s.check(t), c.step)
		})
	}
}

// CheckGrant's inputs: no inner is the caller's error; a message without key 14 has no grant.
func TestCheckGrantInputs(t *testing.T) {
	s := newGrantScene()
	if _, _, err := CheckGrant(nil, &s.keys, s.now); ReasonOf(err) != ReasonInvalidInput {
		t.Fatalf("nil inner: %v", err)
	}
	_, _, err := CheckGrant(&SealedInner{From: s.from, IX: s.inIX}, &s.keys, s.now)
	wantStep(t, err, "decode")
	for name, b := range map[string][]byte{
		"null":           {0xf6},
		"an array":       {0x80},
		"text":           enc(t, "grant"),
		"trailing bytes": append(s.grantBytes(t), 0),
		"truncated":      s.grantBytes(t)[:20],
	} {
		_, _, err := CheckGrant(&SealedInner{From: s.from, IX: s.inIX, Grant: b}, &s.keys, s.now)
		if ReasonOf(err) != ReasonAccessInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A key that is present must hold a value of its own type: a CBOR null is neither an absent key
// nor "" nor false. Read as absent, a null ix would turn a one-shot grant into a peer grant, and a
// null pay or p2p would slip past the placement rules; so each is refused at decode.
func TestGrantNullIsNotAbsent(t *testing.T) {
	s := newGrantScene()
	s.p2p, s.pay = strp("192.0.2.1:1"), boolp(false)
	peer := s.grantBytes(t)
	one := newGrantScene()
	one.ix = strp(one.inIX)
	oneShot := one.grantBytes(t)
	check := func(g []byte) error {
		_, _, err := CheckGrant(&SealedInner{From: s.from, IX: s.inIX, Grant: g}, &s.keys, s.now)
		return err
	}
	for _, g := range [][]byte{peer, oneShot} {
		if err := check(g); err != nil {
			t.Fatalf("the base grant is refused: %v", err)
		}
	}
	for name, c := range map[string]struct {
		base []byte
		key  uint64
	}{
		"cap": {peer, 1}, "holder_seed": {peer, 2}, "home": {peer, 3},
		"ix": {oneShot, 4}, "p2p": {peer, 5}, "pay": {peer, 6},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := decodeFields(c.base)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := m[c.key]; !ok {
				t.Fatalf("the base grant has no key %d", c.key)
			}
			m[c.key] = []byte{0xf6}
			b := mustMarshalFields(t, m)
			wantStep(t, check(b), "decode")
			if _, err := UnmarshalGrant(b); ReasonOf(err) != ReasonAccessInvalid {
				t.Fatalf("UnmarshalGrant: %v", err)
			}
		})
	}
}

// Grant.Marshal refuses what its recipient would ignore whatever the message, and the decoder
// keeps "absent" apart from "empty" and "false".
func TestGrantMarshal(t *testing.T) {
	s := newGrantScene()
	c, err := SignCap(s.signer, &s.body)
	if err != nil {
		t.Fatal(err)
	}
	base := Grant{Cap: *c, HolderSeed: s.seed, Home: s.home}
	b, err := base.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if m, err := decodeFields(b); err != nil || len(m) != 3 {
		t.Fatalf("a grant with the fewest fields has keys %v (%v)", m, err)
	}
	for name, g := range map[string]Grant{
		"empty p2p": {Cap: *c, HolderSeed: s.seed, Home: s.home, P2P: strp("")},
		"pay false": {Cap: *c, HolderSeed: s.seed, Home: s.home, Pay: boolp(false)},
		"empty ix":  {Cap: *c, HolderSeed: s.seed, Home: s.home, IX: strp("")},
		"every key": {Cap: *c, HolderSeed: s.seed, Home: s.home, P2P: strp("192.0.2.1:1"), Pay: boolp(true)},
		"one-shot":  {Cap: *c, HolderSeed: s.seed, Home: s.home, IX: strp("ix-1")},
	} {
		b, err := g.Marshal()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		u, err := UnmarshalGrant(b)
		if err != nil || !reflect.DeepEqual(*u, g) {
			t.Fatalf("%s: round trip %+v (%v)", name, u, err)
		}
	}
	stranger := s.body
	stranger.Class = CapClassStranger
	sc, err := SignCap(s.signer, &stranger)
	if err != nil {
		t.Fatal(err)
	}
	class3 := s.body
	class3.Class = 3
	c3b, _ := class3.Marshal()
	other := ed25519.NewKeyFromSeed(goldenSeed("GRANT-1", "test/other"))
	for name, g := range map[string]*Grant{
		"nil":                     nil,
		"no cap":                  {HolderSeed: s.seed, Home: s.home},
		"short cap sig":           {Cap: Cap{Body: c.Body, Sig: c.Sig[:10]}, HolderSeed: s.seed, Home: s.home},
		"cap body not a CapBody":  {Cap: Cap{Body: []byte("x"), Sig: c.Sig}, HolderSeed: s.seed, Home: s.home},
		"cap body of class 3":     {Cap: Cap{Body: c3b, Sig: c.Sig}, HolderSeed: s.seed, Home: s.home},
		"holder seed of 31 bytes": {Cap: *c, HolderSeed: s.seed[:31], Home: s.home},
		"another holder seed":     {Cap: *c, HolderSeed: other.Seed(), Home: s.home},
		"empty home":              {Cap: *c, HolderSeed: s.seed},
		"home with U+0000":        {Cap: *c, HolderSeed: s.seed, Home: "a\x00b"},
		"p2p in a stranger grant": {Cap: *sc, HolderSeed: s.seed, Home: s.home, P2P: strp("192.0.2.1:1")},
		"p2p in a one-shot grant": {Cap: *c, HolderSeed: s.seed, Home: s.home, IX: strp("i"), P2P: strp("192.0.2.1:1")},
		"pay in a one-shot grant": {Cap: *c, HolderSeed: s.seed, Home: s.home, IX: strp("i"), Pay: boolp(true)},
	} {
		if _, err := g.Marshal(); ReasonOf(err) != ReasonInvalidInput {
			t.Errorf("%s: %v, want invalid-input", name, err)
		}
	}
	if k := base.HolderKey(); !bytes.Equal(k, ed25519.NewKeyFromSeed(s.seed)) {
		t.Fatal("HolderKey is not the key of the seed")
	}
	if (&Grant{HolderSeed: s.seed[:31]}).HolderKey() != nil || (*Grant)(nil).HolderKey() != nil {
		t.Fatal("HolderKey of a malformed seed")
	}
	// The kept grant drives a delivery: its holder key makes the proof VerifyAccess takes.
	d := [32]byte{4}
	a := &Access{Kind: AccessKindCap, Cap: &base.Cap, Proof: SignAccess(base.HolderKey(), s.body.CapID, d)}
	if err := VerifyAccess(a, d, s.keys.Mbox, s.body.Owner, s.now); err != nil {
		t.Fatal(err)
	}
}
