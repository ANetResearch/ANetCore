package seal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// testHomeAID is an AID for a Grant's home (key 3): the conformance hub identity.
var testHomeAID = identity.SuiteController().AID()

// smallOrderEncodings are the 14 encodings of the eight Ed25519 points of small order that a
// lenient decoder accepts: the canonical ones (y < p, both signs where x is not 0, and x = 0 with
// the sign bit set) and y = p, p + 1 written for 0 and 1. They were computed independently of
// smallOrderY (curve arithmetic over the integers: every encoding whose point P has 8P = O).
var smallOrderEncodings = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func smallOrderKeys(t testing.TB) [][]byte {
	t.Helper()
	out := make([][]byte, len(smallOrderEncodings))
	for i, h := range smallOrderEncodings {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			t.Fatalf("%s: %v", h, err)
		}
		out[i] = b
	}
	return out
}

// forge returns a message among msgs and a signature that crypto/ed25519 accepts for it under
// pub, made without any private key: R a point of small order and S = 0, which verifies whenever
// -[k]pub = R. Under a key of small order -[k]pub is one of eight points, so one message in a
// handful has one. It is what a key of small order gives everyone, and why CORE-K8a refuses them.
func forge(pub []byte, msgs func(i int) []byte) (msg, sig []byte, ok bool) {
	var rs [][]byte
	for _, h := range smallOrderEncodings {
		b, _ := hex.DecodeString(h)
		rs = append(rs, b)
	}
	for i := range 256 {
		m := msgs(i)
		for _, r := range rs {
			s := append(bytes.Clone(r), make([]byte, 32)...)
			if ed25519.Verify(pub, m, s) {
				return m, s, true
			}
		}
	}
	return nil, nil, false
}

// CORE-K8a: a mailbox key or a capability holder key of small order is refused, under every
// encoding of the eight points, by the key set structure check (SignEncKeySet and
// VerifyEncKeySet), by SignCap, by VerifyAccess (step decode) and by CheckGrant (step 2, body).
// Before each refusal the test shows the danger it closes: crypto/ed25519 accepts a signature made
// without a private key under that public key. Honest keys still pass every check.
func TestSmallOrderKeysRefused(t *testing.T) {
	keys := smallOrderKeys(t)
	listed := map[string]bool{}
	for _, k := range keys {
		listed[string(k)] = true
	}
	if len(listed) != 14 {
		t.Fatalf("%d distinct small-order encodings, want 14", len(listed))
	}
	// The list and smallOrder agree, over the 14 and over everything one bit away from them.
	for _, k := range keys {
		if !smallOrder(k) {
			t.Errorf("%x is not taken for a key of small order", k)
		}
		for bit := range 8 * len(k) {
			c := bytes.Clone(k)
			c[bit/8] ^= 1 << (bit % 8)
			if smallOrder(c) != listed[string(c)] {
				t.Errorf("%x: smallOrder %v", c, smallOrder(c))
			}
		}
	}
	if smallOrder(keys[0][:31]) || smallOrder(nil) {
		t.Fatal("a key of the wrong length is not a key of small order; the length check says what it is")
	}

	owner := newParty(t)
	honestHolder := ed25519.NewKeyFromSeed(goldenSeed("ACCESS-1", "test/honest-holder"))
	_, honestMbox, _ := ed25519.GenerateKey(nil)
	for i, k := range keys {
		name := smallOrderEncodings[i]
		t.Run(name, func(t *testing.T) {
			// Anyone can sign under this key.
			if _, _, ok := forge(k, func(i int) []byte { return []byte{byte(i), byte(i >> 8)} }); !ok {
				t.Fatal("no forgery found: is this key of small order?")
			}

			// The key set: a small-order mailbox key.
			set := *owner.set
			set.Mbox = Mbox{Epoch: 1, Pub: k}
			if _, err := SignEncKeySet(&set, owner.c.Sign); ReasonOf(err) != ReasonBadKeySet {
				t.Errorf("SignEncKeySet: %v, want %s", err, ReasonBadKeySet)
			}
			if _, err := VerifyEncKeySet(signRaw(t, owner.c, set), owner.aid(), owner.c.KEL(), t0); ReasonOf(err) != ReasonBadKeySet {
				t.Errorf("VerifyEncKeySet: %v, want %s", err, ReasonBadKeySet)
			}

			// SignCap: a small-order holder.
			body := CapBody{Type: CapType, Owner: owner.aid(), Epoch: 1, CapID: bytes.Repeat([]byte{7}, CapIDLen),
				Class: CapClassStranger, CapExp: t0 + dayMS, Holder: k}
			if _, err := SignCap(honestMbox, &body); ReasonOf(err) != ReasonInvalidInput {
				t.Errorf("SignCap: %v, want %s", err, ReasonInvalidInput)
			}

			// VerifyAccess: a capability its owner did sign for a small-order holder, and a proof
			// that ed25519 accepts although nobody holds the holder key. Refused at decode.
			b, err := body.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			c := &Cap{Body: b, Sig: ed25519.Sign(honestMbox, b)}
			var digest [32]byte
			_, proof, ok := forge(k, func(i int) []byte {
				digest = sha256.Sum256([]byte{byte(i), byte(i >> 8)})
				return accessInput(body.CapID, digest)
			})
			if !ok {
				t.Fatal("no forged proof")
			}
			mbox := Mbox{Epoch: 1, Pub: honestMbox.Public().(ed25519.PublicKey)}
			wantStep(t, VerifyAccess(&Access{Kind: AccessKindCap, Cap: c, Proof: proof}, digest, mbox, owner.aid(), t0), "decode")
			if _, err := UnmarshalCapBody(b); ReasonOf(err) != ReasonAccessInvalid {
				t.Errorf("UnmarshalCapBody: %v", err)
			}

			// VerifyAccess and CheckGrant with a small-order mailbox key: refused at sig, though
			// a forged capability signature verifies under it.
			hb := body
			hb.Holder = honestHolder.Public().(ed25519.PublicKey)
			hbb, csig, ok := forge(k, func(i int) []byte {
				id := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
				hb.CapID = id[:CapIDLen]
				b, err := hb.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				return b
			})
			if !ok {
				t.Fatal("no forged capability signature")
			}
			fc := Cap{Body: hbb, Sig: csig}
			fbody, err := UnmarshalCapBody(hbb)
			if err != nil {
				t.Fatal(err)
			}
			d := [32]byte{9}
			a := &Access{Kind: AccessKindCap, Cap: &fc, Proof: SignAccess(honestHolder, fbody.CapID, d)}
			wantStep(t, VerifyAccess(a, d, Mbox{Epoch: 1, Pub: k}, owner.aid(), t0), "sig")
			fg, err := coredet.Marshal(Grant{Cap: fc, HolderSeed: honestHolder.Seed(), Home: testHomeAID})
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = CheckGrant(&SealedInner{From: owner.aid(), IX: "ix-1", Grant: fg}, &EncKeySet{AID: owner.aid(), Mbox: Mbox{Epoch: 1, Pub: k}}, t0)
			wantStep(t, err, "sig")

			// CheckGrant: the sender hands over a capability for a small-order holder. Step 2.
			g := Grant{Cap: *c, HolderSeed: honestHolder.Seed(), Home: testHomeAID}
			graw, err := coredet.Marshal(g)
			if err != nil {
				t.Fatal(err)
			}
			keysOf := &EncKeySet{AID: owner.aid(), Mbox: mbox}
			_, _, err = CheckGrant(&SealedInner{From: owner.aid(), IX: "ix-1", Grant: graw}, keysOf, t0)
			wantStep(t, err, "body")
			if _, err := g.Marshal(); ReasonOf(err) != ReasonInvalidInput {
				t.Errorf("Grant.Marshal: %v, want %s", err, ReasonInvalidInput)
			}
		})
	}

	// Honest keys pass each of the four.
	t.Run("honest keys", func(t *testing.T) {
		if _, err := VerifyEncKeySet(owner.signed, owner.aid(), owner.c.KEL(), t0); err != nil {
			t.Fatal(err)
		}
		body := CapBody{Type: CapType, Owner: owner.aid(), Epoch: 1, CapID: bytes.Repeat([]byte{7}, CapIDLen),
			Class: CapClassContact, CapExp: t0 + dayMS, Holder: honestHolder.Public().(ed25519.PublicKey)}
		c, err := SignCap(honestMbox, &body)
		if err != nil {
			t.Fatal(err)
		}
		mbox := Mbox{Epoch: 1, Pub: honestMbox.Public().(ed25519.PublicKey)}
		d := [32]byte{5}
		a := &Access{Kind: AccessKindCap, Cap: c, Proof: SignAccess(honestHolder, body.CapID, d)}
		wantStep(t, VerifyAccess(a, d, mbox, owner.aid(), t0), "")
		graw, err := (&Grant{Cap: *c, HolderSeed: honestHolder.Seed(), Home: testHomeAID}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := CheckGrant(&SealedInner{From: owner.aid(), IX: "ix-1", Grant: graw}, &EncKeySet{AID: owner.aid(), Mbox: mbox}, t0); err != nil {
			t.Fatal(err)
		}
		for range 1000 {
			pub, _, _ := ed25519.GenerateKey(nil)
			if smallOrder(pub) {
				t.Fatalf("a generated key %x is taken for one of small order", pub)
			}
		}
	})
}
