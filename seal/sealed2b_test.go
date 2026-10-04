package seal

// SEALED-2B (core §5.2; FS §7.1): seal/testdata/vec-sealed-2b.json, one two-layer envelope
// written by golden/py/gen_v016.py. Go derives the recipient's epoch key and interaction key
// from their seeds, opens the bytes, and reproduces every value that does not depend on the
// HPKE ephemeral keys (CORE-G2).

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

const fileSealed2B = "testdata/vec-sealed-2b.json"

// vecIX is a recipient interaction key as the seal vectors write it.
type vecIX struct {
	IX       string   `json:"ix"`
	Peer     string   `json:"peer"`
	SeedRole string   `json:"seed_role"`
	SK       hexBytes `json:"sk"`
	Pub      hexBytes `json:"pub"`
	KID      hexBytes `json:"kid"`
}

// key derives the interaction key from the seed of vid and checks it against the file.
func (v *vecIX) key(t *testing.T, vid, sender string) *IXKey {
	t.Helper()
	kp, err := DeriveKeyPair(SuiteX25519, goldenSeed(vid, v.SeedRole), 0, dayMS)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.Public.Pub, v.Pub) || !bytes.Equal(kp.Public.KID, v.KID) || v.Peer != sender {
		t.Fatalf("%s: the interaction key from the seed is not the file's", vid)
	}
	sk, err := params(SuiteX25519).kem.NewPrivateKey(v.SK)
	if err != nil || !bytes.Equal(sk.PublicKey().Bytes(), v.Pub) {
		t.Fatalf("%s: the file's interaction sk is not the key of its pub (%v)", vid, err)
	}
	return &IXKey{IX: v.IX, PeerAID: v.Peer, Suite: SuiteX25519, Pub: kp.Public.Pub, Private: kp.Private}
}

type vecSealed2B struct {
	vecParties
	RecipientIX   vecIX `json:"recipient_ix"`
	RecipientMbox struct {
		Epoch    uint64   `json:"epoch"`
		SeedRole string   `json:"seed_role"`
		Pub      hexBytes `json:"pub"`
	} `json:"recipient_mbox"`
	HPKEInfo hexBytes `json:"hpke_info"`
	IXInfo   hexBytes `json:"ix_info"`
	Inner    struct {
		From        string   `json:"from"`
		KeyStateSeq uint64   `json:"key_state_seq"`
		To          string   `json:"to"`
		Type        string   `json:"type"`
		IX          string   `json:"ix"`
		MID         hexBytes `json:"mid"`
		TS          uint64   `json:"ts"`
		Exp         uint64   `json:"exp"`
		Body        hexBytes `json:"body"`
		RK          struct {
			Suite Suite    `json:"suite"`
			Pub   hexBytes `json:"pub"`
		} `json:"rk"`
		Ext map[string]hexBytes `json:"ext"`
		Sig hexBytes            `json:"sig"`
	} `json:"inner"`
	InnerCBOR   hexBytes            `json:"inner_cbor"`
	SigPreimage hexBytes            `json:"sig_preimage"`
	Enc2        hexBytes            `json:"enc2"`
	CT2         hexBytes            `json:"ct2"`
	Wrap        hexBytes            `json:"wrap"`
	PadLen      int                 `json:"pad_len"`
	Enc         hexBytes            `json:"enc"`
	OuterExt    map[string]hexBytes `json:"outer_ext"`
	Sealed      hexBytes            `json:"sealed"`
	Access      hexBytes            `json:"access"`
	AccessParts struct {
		CapBody   hexBytes `json:"cap_body"`
		CapSig    hexBytes `json:"cap_sig"`
		CapID     hexBytes `json:"cap_id"`
		HolderPub hexBytes `json:"holder_pub"`
		Proof     hexBytes `json:"proof"`
	} `json:"access_parts"`
	Envelope    hexBytes `json:"envelope"`
	EnvDigest   hexBytes `json:"env_digest"`
	AckKey      hexBytes `json:"ack_key"`
	Handle      hexBytes `json:"handle"`
	Tok1        hexBytes `json:"tok1"`
	Tok2        hexBytes `json:"tok2"`
	SingleLayer struct {
		Envelope    hexBytes `json:"envelope"`
		SigPreimage hexBytes `json:"sig_preimage"`
		AckKey      hexBytes `json:"ack_key"`
	} `json:"single_layer"`
	Negatives []struct {
		Name     string   `json:"name"`
		Envelope hexBytes `json:"envelope"`
		Reason   string   `json:"reason"`
	} `json:"negatives"`
}

func TestSEALED_2B(t *testing.T) {
	const vid = "SEALED-2B"
	var v vecSealed2B
	readVector(t, fileSealed2B, &v)
	kp, senderPub := v.keys(t, vid)
	ixKey := v.RecipientIX.key(t, vid, v.Sender.AID)
	look := ixKeys{ixKey}

	info, err := HPKEInfo(v.Recipient.AID, SuiteX25519, kp.Public.KID)
	if err != nil || !bytes.Equal(info, v.HPKEInfo) {
		t.Fatalf("hpke info %x, file %x (%v)", info, v.HPKEInfo, err)
	}
	ixInfo, err := IXInfo(v.Recipient.AID, SuiteX25519, ixKey.KID())
	if err != nil || !bytes.Equal(ixInfo, v.IXInfo) {
		t.Fatalf("layer-2 info %x, file %x (%v)", ixInfo, v.IXInfo, err)
	}
	o, err := Open(v.Envelope, v.Recipient.AID, StaticKeyRing{kp}, look)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Run("outer", func(t *testing.T) {
		if o.Outer.V != 2 || o.Outer.To != v.Recipient.AID || o.Outer.Suite != SuiteX25519 ||
			!bytes.Equal(o.Outer.KID, kp.Public.KID) || !bytes.Equal(o.Outer.Enc, v.Enc) ||
			o.Outer.Exp == nil || *o.Outer.Exp != v.Inner.Exp || o.Layers != 2 || !bytes.Equal(o.IKID, v.RecipientIX.KID) {
			t.Fatalf("outer %+v, layers %d, ikid %x", o.Outer, o.Layers, o.IKID)
		}
		fields, err := decodeFields(v.Envelope)
		if err != nil || !bytes.Equal(fields[64], v.OuterExt["64"]) {
			t.Fatalf("outer extension key 64 (%v)", err)
		}
		// Seal's form plus the access is the envelope; env_digest covers key 64 and key 8, not
		// key 7 (L4).
		env, err := SetAccess(v.Sealed, o.Access)
		if err != nil || !bytes.Equal(env, v.Envelope) {
			t.Fatalf("SetAccess(sealed, access) is not the envelope (%v)", err)
		}
		for _, b := range [][]byte{v.Envelope, v.Sealed} {
			d, err := EnvDigest(b)
			if err != nil || !bytes.Equal(d[:], v.EnvDigest) {
				t.Fatalf("env_digest %x, file %x (%v)", d, v.EnvDigest, err)
			}
		}
		delete(fields, 64)
		delete(fields, outerKeyAccess)
		if d, _ := EnvDigest(mustMarshalFields(t, fields)); bytes.Equal(d[:], v.EnvDigest) {
			t.Fatal("env_digest does not cover the extension key")
		}
	})
	t.Run("access", func(t *testing.T) {
		// Kind 1 (core §2.1): the capability the recipient issued, signed by its mailbox key
		// (L6), and the holder's proof over env_digest (L5).
		a := o.Access
		if a == nil || a.Kind != AccessKindCap || a.Cap == nil || !bytes.Equal(a.Cap.Body, v.AccessParts.CapBody) ||
			!bytes.Equal(a.Cap.Sig, v.AccessParts.CapSig) || !bytes.Equal(a.Proof, v.AccessParts.Proof) {
			t.Fatalf("access %+v", a)
		}
		if b, err := encodeAccess(a); err != nil || !bytes.Equal(b, v.Access) {
			t.Fatalf("access encoding (%v)", err)
		}
		mbox := ed25519.NewKeyFromSeed(goldenSeed(vid, v.RecipientMbox.SeedRole)).Public().(ed25519.PublicKey)
		if !bytes.Equal(mbox, v.RecipientMbox.Pub) || v.RecipientMbox.Epoch != 1 {
			t.Fatal("the mailbox key from the seed is not the file's")
		}
		if !ed25519.Verify(mbox, a.Cap.Body, a.Cap.Sig) {
			t.Fatal("the capability is not signed by the recipient's mailbox key (L6)")
		}
		body, err := decodeFields(a.Cap.Body)
		if err != nil {
			t.Fatal(err)
		}
		tag, _ := rawText(body, 0)
		owner, _ := rawText(body, 1)
		epoch, _ := rawUint(body, 2)
		capID, _ := rawBytes(body, 3)
		class, _ := rawUint(body, 4)
		holder, _ := rawBytes(body, 6)
		if tag != "anet.cap/1" || owner != o.Outer.To || epoch != v.RecipientMbox.Epoch || class != 1 ||
			!bytes.Equal(capID, v.AccessParts.CapID) || !bytes.Equal(holder, v.AccessParts.HolderPub) {
			t.Fatalf("CapBody %v", body)
		}
		if !bytes.Equal(mustMarshalFields(t, body), a.Cap.Body) {
			t.Fatal("CapBody is not CoreDet (CORE-E2)")
		}
		msg := append(append([]byte("anet-access/v2\x00"), capID...), v.EnvDigest...)
		if !ed25519.Verify(ed25519.PublicKey(holder), msg, a.Proof) {
			t.Fatal("the proof is not the holder's over env_digest (L5)")
		}
	})
	t.Run("wrap and second layer", func(t *testing.T) {
		wrap := openLayer1(t, v.Envelope, kp)
		if !bytes.Equal(wrap, v.Wrap) || Padme(len(wrap)) != len(wrap) {
			t.Fatalf("layer-1 plaintext is not the file's Wrap, or not on a Padmé length (%d bytes)", len(wrap))
		}
		w, err := decodeWrap(wrap)
		if err != nil || !bytes.Equal(w.ikid, ixKey.KID()) || !bytes.Equal(w.enc2, v.Enc2) || !bytes.Equal(w.body, v.CT2) {
			t.Fatalf("Wrap fields (%v)", err)
		}
		// The Go padding of the same ikid, enc2 and ciphertext gives the same Wrap.
		m, n, err := (&wrapFields{ikid: w.ikid, enc2: w.enc2, body: w.body}).paddedMap()
		if err != nil || n != len(v.Wrap) || !bytes.Equal(mustMarshalFields(t, m), v.Wrap) {
			t.Fatalf("Go pads the Wrap to %d bytes, the file to %d (%v)", n, len(v.Wrap), err)
		}
		_, inner := openBoth(t, v.Envelope, kp, ixKey)
		if !bytes.Equal(inner, v.InnerCBOR) {
			t.Fatal("the second layer does not hold the file's inner, unpadded")
		}
	})
	t.Run("inner", func(t *testing.T) {
		in, want := o.Inner, v.Inner
		if in.From != want.From || in.From != v.Sender.AID || in.KeyStateSeq != want.KeyStateSeq || in.To != want.To ||
			in.Type != want.Type || in.IX != want.IX || in.IX != v.RecipientIX.IX || !bytes.Equal(in.MID, want.MID) ||
			in.TS != want.TS || in.Exp != want.Exp || !bytes.Equal(in.Body, want.Body) || in.KEL != nil ||
			in.Notices != nil || in.Keys != nil || in.Grant != nil || in.RK == nil || in.RK.Suite != want.RK.Suite ||
			!bytes.Equal(in.RK.Pub, want.RK.Pub) || !bytes.Equal(in.Sig, want.Sig) || len(in.Ext) != 1 ||
			!bytes.Equal(in.Ext[64], want.Ext["64"]) {
			t.Fatalf("opened inner %+v\nfile %+v", in, want)
		}
		if o.RK != in.RK || o.Access != o.Outer.Access {
			t.Fatal("Opened.RK or Access is not the opened value's (CORE-A2)")
		}
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
		if !bytes.Equal(designPreimage(t, fields, v.Enc, kp.Public.KID, 1, v.RecipientIX.KID, v.Enc2), v.SigPreimage) {
			t.Fatal("the file's preimage does not follow core §3.3 with a second layer")
		}
		if !ed25519.Verify(senderPub, o.Preimage, o.Inner.Sig) {
			t.Fatal("the signature does not verify under the sender's current key")
		}
		kel, err := ParseKEL(v.Sender.KEL)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyInnerSig(&o.Inner, o.Preimage, kel, v.Inner.TS+minuteMS); err != nil {
			t.Fatal(err)
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
	t.Run("single layer, same layer 1", func(t *testing.T) {
		// FS-C14: the same message as one layer, under the same layer-1 ephemeral key, gives
		// the same ack_key; only the preimage's second-layer keys differ.
		s, err := Open(v.SingleLayer.Envelope, v.Recipient.AID, StaticKeyRing{kp}, nil)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if s.Layers != 1 || s.IKID != nil || !bytes.Equal(s.Outer.Enc, o.Outer.Enc) {
			t.Fatalf("layers %d; same enc %v", s.Layers, bytes.Equal(s.Outer.Enc, o.Outer.Enc))
		}
		if s.AckKey != o.AckKey || !bytes.Equal(s.AckKey[:], v.SingleLayer.AckKey) {
			t.Fatalf("single-layer ack_key %x, two-layer %x", s.AckKey, o.AckKey)
		}
		if !bytes.Equal(s.Preimage, v.SingleLayer.SigPreimage) || bytes.Equal(s.Preimage, o.Preimage) {
			t.Fatal("single-layer preimage")
		}
		if !ed25519.Verify(senderPub, s.Preimage, s.Inner.Sig) {
			t.Fatal("the single-layer signature does not verify")
		}
		if ed25519.Verify(senderPub, s.Preimage, o.Inner.Sig) || ed25519.Verify(senderPub, o.Preimage, s.Inner.Sig) {
			t.Fatal("a signature verifies under the other layering (SI-31)")
		}
	})
	t.Run("negatives", func(t *testing.T) {
		if len(v.Negatives) != 3 {
			t.Fatalf("%d negatives, want 3", len(v.Negatives))
		}
		for _, n := range v.Negatives {
			_, err := Open(n.Envelope, v.Recipient.AID, StaticKeyRing{kp}, look)
			wantOpenFails(t, err, n.Reason, true)
		}
	})
	t.Run("without the interaction key", func(t *testing.T) {
		_, err := Open(v.Envelope, v.Recipient.AID, StaticKeyRing{kp}, ixKeys{})
		wantOpenFails(t, err, ReasonSealedToClosedInteraction, true)
		if k, _ := AckKeyOf(err); !bytes.Equal(k[:], v.AckKey) {
			t.Fatal("the closed-interaction refusal carries another ack_key")
		}
	})
}
