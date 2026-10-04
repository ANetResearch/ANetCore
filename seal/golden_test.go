package seal

// The seal v2 golden vectors of core §5.2. golden/py/gen_v016.py writes them from public
// seeds with an independent implementation (CORE-G3); the HPKE ephemeral key of each
// envelope is DeriveKeyPair(seed), which Go's crypto/hpke cannot fix, so Go opens the bytes
// and reproduces every value that does not depend on that key (CORE-G2).
//
//	SEALED-2A  seal/testdata/vec-sealed-2a.json  one valid single-layer envelope
//	SEALED-2C  seal/testdata/vec-sealed-2c.json  negatives, each with its seal reason

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

const (
	fileSealed2A = "testdata/vec-sealed-2a.json"
	fileSealed2C = "testdata/vec-sealed-2c.json"
)

// goldenSeed is the published seed rule of the vectors (CORE-G5).
func goldenSeed(vid, role string) []byte {
	h := sha256.Sum256([]byte("anet-golden/v016/" + vid + "/" + role))
	return h[:]
}

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := hex.DecodeString(s)
	*h = v
	return err
}

// vecParties is the part both vectors share.
type vecParties struct {
	Recipient struct {
		AID string   `json:"aid"`
		SK  hexBytes `json:"sk"`
		Pub hexBytes `json:"pub"`
		KID hexBytes `json:"kid"`
	} `json:"recipient"`
	Sender struct {
		AID         string   `json:"aid"`
		KeyStateSeq uint64   `json:"key_state_seq"`
		Pub         hexBytes `json:"pub"`
		KEL         hexBytes `json:"kel"`
	} `json:"sender"`
	Witness struct {
		AID string   `json:"aid"`
		Pub hexBytes `json:"pub"`
		KEL hexBytes `json:"kel"`
	} `json:"witness"`
}

// keys reproduces the recipient's epoch key and the sender's key from the seeds of vid and
// checks them against the file.
func (p *vecParties) keys(t *testing.T, vid string) (*KeyPair, ed25519.PublicKey) {
	t.Helper()
	kp, err := DeriveKeyPair(SuiteX25519, goldenSeed(vid, "recipient-enc"), 0, dayMS)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.Public.Pub, p.Recipient.Pub) || !bytes.Equal(kp.Public.KID, p.Recipient.KID) {
		t.Fatalf("%s: the recipient key from the seed is not the file's", vid)
	}
	// The file gives sk as RFC 9180 DeriveKeyPair outputs it; crypto/hpke returns the clamped
	// form of the same X25519 scalar. Both have the file's public key.
	sk, err := params(SuiteX25519).kem.NewPrivateKey(p.Recipient.SK)
	if err != nil || !bytes.Equal(sk.PublicKey().Bytes(), p.Recipient.Pub) {
		t.Fatalf("%s: the file's sk is not the key of its pub (%v)", vid, err)
	}
	pub := ed25519.NewKeyFromSeed(goldenSeed(vid, "k1")).Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, p.Sender.Pub) {
		t.Fatalf("%s: the sender key from the seed is not the file's", vid)
	}
	return kp, pub
}

func readVector(tb testing.TB, path string, v any) {
	tb.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		tb.Fatalf("%s: %v", path, err)
	}
}

type vecSealed2A struct {
	vecParties
	HPKEInfo hexBytes `json:"hpke_info"`
	Inner    struct {
		From        string     `json:"from"`
		KeyStateSeq uint64     `json:"key_state_seq"`
		To          string     `json:"to"`
		Type        string     `json:"type"`
		IX          string     `json:"ix"`
		MID         hexBytes   `json:"mid"`
		TS          uint64     `json:"ts"`
		Exp         uint64     `json:"exp"`
		Body        hexBytes   `json:"body"`
		KEL         hexBytes   `json:"kel"`
		Notice      []hexBytes `json:"notice"`
		Keys        hexBytes   `json:"keys"`
		Grant       hexBytes   `json:"grant"`
		RK          struct {
			Suite Suite    `json:"suite"`
			Pub   hexBytes `json:"pub"`
		} `json:"rk"`
		Sig hexBytes `json:"sig"`
	} `json:"inner"`
	InnerCBOR   hexBytes `json:"inner_cbor"`
	SigPreimage hexBytes `json:"sig_preimage"`
	Wrap        hexBytes `json:"wrap"`
	PadLen      int      `json:"pad_len"`
	Enc         hexBytes `json:"enc"`
	Sealed      hexBytes `json:"sealed"`
	Access      hexBytes `json:"access"`
	Envelope    hexBytes `json:"envelope"`
	EnvDigest   hexBytes `json:"env_digest"`
	AckKey      hexBytes `json:"ack_key"`
	Handle      hexBytes `json:"handle"`
	Tok1        hexBytes `json:"tok1"`
	Tok2        hexBytes `json:"tok2"`
	Negatives   []struct {
		Name     string   `json:"name"`
		Envelope hexBytes `json:"envelope"`
		Reason   string   `json:"reason"`
	} `json:"negatives"`
}

// hmac16 is the first 16 bytes of HMAC-SHA256(key, msg): the form of handle and tok (L12,
// L13). seal/dack.go (RC-1) owns the token functions; the vector pins the values here.
func hmac16(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:16]
}

func TestSEALED_2A(t *testing.T) {
	var v vecSealed2A
	readVector(t, fileSealed2A, &v)
	kp, senderPub := v.keys(t, "SEALED-2A")

	info, err := HPKEInfo(v.Recipient.AID, SuiteX25519, kp.Public.KID)
	if err != nil || !bytes.Equal(info, v.HPKEInfo) {
		t.Fatalf("hpke info %x, file %x (%v)", info, v.HPKEInfo, err)
	}
	o, err := Open(v.Envelope, v.Recipient.AID, StaticKeyRing{kp}, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Run("outer", func(t *testing.T) {
		if o.Outer.V != 2 || o.Outer.To != v.Recipient.AID || o.Outer.Suite != SuiteX25519 ||
			!bytes.Equal(o.Outer.KID, kp.Public.KID) || !bytes.Equal(o.Outer.Enc, v.Enc) ||
			o.Outer.Access == nil || o.Outer.Access.Kind != AccessKindSession || o.Outer.Exp != nil || o.Layers != 1 {
			t.Fatalf("outer %+v layers %d", o.Outer, o.Layers)
		}
		// Seal's form (no key 7) plus the access is the envelope, and the
		// access does not enter env_digest.
		a, err := decodeAccess(v.Access)
		if err != nil {
			t.Fatal(err)
		}
		env, err := SetAccess(v.Sealed, a)
		if err != nil || !bytes.Equal(env, v.Envelope) {
			t.Fatalf("SetAccess(sealed, access) is not the envelope (%v)", err)
		}
		for _, b := range [][]byte{v.Envelope, v.Sealed} {
			d, err := EnvDigest(b)
			if err != nil || !bytes.Equal(d[:], v.EnvDigest) {
				t.Fatalf("env_digest %x, file %x (%v)", d, v.EnvDigest, err)
			}
		}
	})
	t.Run("wrap", func(t *testing.T) {
		wrap := openLayer1(t, v.Envelope, kp)
		if !bytes.Equal(wrap, v.Wrap) {
			t.Fatal("layer-1 plaintext is not the file's Wrap")
		}
		if Padme(len(wrap)) != len(wrap) {
			t.Fatalf("Wrap is %d bytes, not a Padmé length", len(wrap))
		}
		// The Go padding of the same inner gives the same Wrap.
		if got := wrapOf(t, v.InnerCBOR); !bytes.Equal(got, v.Wrap) {
			t.Fatalf("Go pads the inner to %d bytes, the file to %d", len(got), len(v.Wrap))
		}
		w, err := decodeWrap(wrap)
		if err != nil || w.ikid != nil || !bytes.Equal(w.body, v.InnerCBOR) {
			t.Fatalf("wrap body (%v)", err)
		}
	})
	t.Run("inner", func(t *testing.T) {
		in, want := o.Inner, v.Inner
		if in.From != want.From || in.From != v.Sender.AID || in.KeyStateSeq != want.KeyStateSeq || in.To != want.To ||
			in.Type != want.Type || in.IX != want.IX || !bytes.Equal(in.MID, want.MID) || in.TS != want.TS ||
			in.Exp != want.Exp || !bytes.Equal(in.Body, want.Body) || !bytes.Equal(in.KEL, want.KEL) ||
			!bytes.Equal(in.KEL, v.Sender.KEL) || len(in.Notices) != 1 || len(want.Notice) != 1 ||
			!bytes.Equal(in.Notices[0], want.Notice[0]) || !bytes.Equal(in.Keys, want.Keys) ||
			!bytes.Equal(in.Grant, want.Grant) || in.RK == nil || in.RK.Suite != want.RK.Suite ||
			!bytes.Equal(in.RK.Pub, want.RK.Pub) || !bytes.Equal(in.Sig, want.Sig) || in.Ext != nil {
			t.Fatalf("opened inner %+v\nfile %+v", in, want)
		}
		if len(o.KEL) != 2 {
			t.Fatalf("KEL of %d events, want 2", len(o.KEL))
		}
		if o.RK != in.RK || len(o.Notices) != 1 || !bytes.Equal(o.Notices[0], want.Notice[0]) ||
			!bytes.Equal(o.Grant, want.Grant) || o.Access != o.Outer.Access {
			t.Fatal("Opened.RK, Notices, Grant or Access is not the opened inner's (CORE-A2)")
		}
		// Go encodes the same fields to the same inner bytes.
		g := in
		g.Sig = nil
		fields, err := g.fieldMap()
		if err != nil {
			t.Fatal(err)
		}
		fields[keySig] = enc(t, want.Sig)
		if !bytes.Equal(mustMarshalFields(t, fields), v.InnerCBOR) {
			t.Fatal("Go encodes the inner differently")
		}
	})
	t.Run("preimage and signature", func(t *testing.T) {
		if !bytes.Equal(o.Preimage, v.SigPreimage) {
			t.Fatalf("preimage\n got  %x\n file %x", o.Preimage, v.SigPreimage)
		}
		fields, err := decodeFields(v.InnerCBOR)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(designPreimage(t, fields, v.Enc, kp.Public.KID, 1, nil, nil), v.SigPreimage) {
			t.Fatal("the file's preimage does not follow core §3.3")
		}
		if !ed25519.Verify(senderPub, o.Preimage, o.Inner.Sig) {
			t.Fatal("the signature does not verify under the sender's current key")
		}
	})
	t.Run("ack_key, handle, tok", func(t *testing.T) {
		if !bytes.Equal(o.AckKey[:], v.AckKey) {
			t.Fatalf("ack_key %x, file %x", o.AckKey, v.AckKey)
		}
		if !bytes.Equal(hmac16(o.AckKey[:], []byte("anet-dack-handle/v1")), v.Handle) ||
			!bytes.Equal(hmac16(o.AckKey[:], []byte("anet-dack-tok/v1\x01")), v.Tok1) ||
			!bytes.Equal(hmac16(o.AckKey[:], []byte("anet-dack-tok/v1\x02")), v.Tok2) {
			t.Fatal("handle or tok differs from the file")
		}
	})
	t.Run("signature under the KEL", func(t *testing.T) {
		if err := VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, v.Inner.TS+minuteMS, DefaultRotationGrace); err != nil {
			t.Fatal(err)
		}
	})
	// The objects inside the inner pass their own checks, so a change of their layout turns this
	// vector red here (core §5.2): key 12 under VerifyEncKeySet, key 14 under CheckGrant.
	mbox := ed25519.NewKeyFromSeed(goldenSeed("SEALED-2A", "mbox"))
	var set *EncKeySet
	t.Run("key set under the KEL", func(t *testing.T) {
		signed, err := UnmarshalSignedEncKeySet(o.Inner.Keys)
		if err != nil {
			t.Fatal(err)
		}
		if set, err = VerifyEncKeySet(signed, o.Inner.From, o.KEL, v.Inner.TS+minuteMS); err != nil {
			t.Fatal(err)
		}
		if signed.KeyStateSeq != v.Sender.KeyStateSeq || set.AID != v.Sender.AID || len(set.Keys) != 1 ||
			set.Mbox.Epoch != 1 || !bytes.Equal(set.Mbox.Pub, mbox.Public().(ed25519.PublicKey)) {
			t.Fatalf("key set %+v signed at %d", set, signed.KeyStateSeq)
		}
		re, err := set.Marshal()
		if err != nil || !bytes.Equal(re, signed.Set) {
			t.Fatalf("Go encodes the key set differently (%v)", err)
		}
	})
	t.Run("grant", func(t *testing.T) {
		if set == nil {
			t.Fatal("the key set the grant is checked against did not verify")
		}
		g, body, err := CheckGrant(&o.Inner, set, v.Inner.TS+minuteMS)
		if err != nil {
			t.Fatal(err)
		}
		holder := ed25519.NewKeyFromSeed(goldenSeed("SEALED-2A", "holder"))
		want := CapBody{Type: CapType, Owner: v.Sender.AID, Epoch: 1, CapID: goldenSeed("SEALED-2A", "cap-id")[:CapIDLen],
			Class: CapClassContact, CapExp: v.Inner.TS + 30*dayMS, Holder: holder.Public().(ed25519.PublicKey)}
		if !reflect.DeepEqual(*body, want) || !bytes.Equal(g.HolderSeed, holder.Seed()) || g.Home != v.Witness.AID ||
			g.IX != nil || g.P2P != nil || g.Pay != nil {
			t.Fatalf("grant %+v, cap body %+v", g, body)
		}
		// Go issues the same grant: the same capability bytes and signature, the same grant bytes.
		c, err := SignCap(mbox, &want)
		if err != nil || !reflect.DeepEqual(*c, g.Cap) {
			t.Fatalf("SignCap gives %+v (%v)", c, err)
		}
		b, err := (&Grant{Cap: *c, HolderSeed: holder.Seed(), Home: v.Witness.AID}).Marshal()
		if err != nil || !bytes.Equal(b, v.Inner.Grant) {
			t.Fatalf("Go encodes the grant differently (%v)", err)
		}
	})
	t.Run("negatives", func(t *testing.T) {
		if len(v.Negatives) != 3 {
			t.Fatalf("%d negatives, want 3", len(v.Negatives))
		}
		for _, n := range v.Negatives {
			_, err := Open(n.Envelope, v.Recipient.AID, StaticKeyRing{kp}, nil)
			if ReasonOf(err) != n.Reason {
				t.Errorf("%s: %v, want %s", n.Name, err, n.Reason)
			}
			if _, ok := AckKeyOf(err); ok {
				t.Errorf("%s: an ack_key before layer 1 opened", n.Name)
			}
		}
	})
}

type vecSealed2C struct {
	vecParties
	Cases []struct {
		Name        string   `json:"name"`
		Stage       string   `json:"stage"`
		Reason      string   `json:"reason"`
		Envelope    hexBytes `json:"envelope"`
		SigPreimage hexBytes `json:"sig_preimage"`
		ReceiptBody hexBytes `json:"receipt_body"`
	} `json:"cases"`
}

// Each negative fails at its step with its reason, and with an ack_key exactly when layer 1
// opened; the valid cases open and verify.
func TestSEALED_2C(t *testing.T) {
	var v vecSealed2C
	readVector(t, fileSealed2C, &v)
	kp, senderPub := v.keys(t, "SEALED-2C")
	ring := StaticKeyRing{kp}
	seen := map[string]bool{}
	for _, c := range v.Cases {
		seen[c.Reason] = true
		t.Run(c.Name, func(t *testing.T) {
			_, perr := ParseOuter(c.Envelope)
			o, err := Open(c.Envelope, v.Recipient.AID, ring, nil)
			switch c.Stage {
			case "parse":
				wantOpenFails(t, perr, c.Reason, false)
				wantOpenFails(t, err, c.Reason, false)
			case "open":
				if perr != nil {
					t.Fatalf("ParseOuter: %v", perr)
				}
				wantOpenFails(t, err, c.Reason, true)
			case "sig":
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				if !bytes.Equal(o.Preimage, c.SigPreimage) {
					t.Fatal("preimage differs from the file")
				}
				fields := decryptFields(t, c.Envelope, kp)
				if !bytes.Equal(designPreimage(t, fields, o.Outer.Enc, o.Outer.KID, 1, nil, nil), c.SigPreimage) {
					t.Fatal("the file's preimage does not follow core §3.3")
				}
				ok := ed25519.Verify(senderPub, o.Preimage, o.Inner.Sig)
				if ok != (c.Reason == "") {
					t.Fatalf("signature verifies: %v, want reason %q", ok, c.Reason)
				}
				if c.ReceiptBody != nil {
					// SI-81: a real signature by the same key, over a
					// ReceiptBody, does not pass as the inner's.
					if !ed25519.Verify(senderPub, c.ReceiptBody, o.Inner.Sig) {
						t.Fatal("the case's signature is not the sender's over the ReceiptBody")
					}
				}
			default:
				t.Fatalf("stage %q", c.Stage)
			}
		})
	}
	for _, r := range []string{"", ReasonBadVersion, ReasonUnknownField, ReasonAccessInvalid, ReasonBadWrap,
		ReasonExpMismatch, ReasonBadInner, ReasonBadKEL, ReasonBadSig} {
		if !seen[r] {
			t.Errorf("no case with reason %q", r)
		}
	}
	t.Run("bad-sig under the KEL", func(t *testing.T) {
		for _, c := range v.Cases {
			if c.Stage != "sig" {
				continue
			}
			o, err := Open(c.Envelope, v.Recipient.AID, ring, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = VerifyInnerSig(&o.Inner, o.Preimage, o.KEL, o.Inner.TS+minuteMS, DefaultRotationGrace)
			if ReasonOf(err) != c.Reason {
				t.Errorf("%s: %v, want %q", c.Name, err, c.Reason)
			}
		}
	})
}
