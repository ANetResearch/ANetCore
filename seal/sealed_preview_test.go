package seal

// SEALED-PREVIEW-1 (core §5.2; CUX §7.1): seal/testdata/vec-sealed-preview-1.json, a preview frame
// written by golden/py/gen_v016.py. Go derives the recipient's epoch key and interaction key from
// their seeds, opens the two layers, reproduces the preimage, the signature check, env_digest and
// ack_key (CORE-G2), and reads the body as the delegation package does: a ChatMsg of kind
// stream_preview that passes ValidatePreview (CUX-P2).

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ANetResearch/ANetCore/delegation"
)

const fileSealedPreview = "testdata/vec-sealed-preview-1.json"

type vecSealedPreview struct {
	vecParties
	RecipientIX vecIX    `json:"recipient_ix"`
	HPKEInfo    hexBytes `json:"hpke_info"`
	IXInfo      hexBytes `json:"ix_info"`
	Frame       struct {
		Kind             string `json:"kind"`
		Body             string `json:"body"`
		StreamSeq        uint64 `json:"stream_seq"`
		StreamAtMS       int64  `json:"stream_at_ms"`
		ReasoningBody    string `json:"reasoning_body"`
		ReasoningAtMS    int64  `json:"reasoning_at_ms"`
		MsgID            string `json:"msg_id"`
		Omitted          uint64 `json:"omitted"`
		ReasoningOmitted uint64 `json:"reasoning_omitted"`
		Answers          string `json:"answers"`
	} `json:"frame"`
	Inner struct {
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
		Sig hexBytes `json:"sig"`
	} `json:"inner"`
	InnerCBOR   hexBytes `json:"inner_cbor"`
	SigPreimage hexBytes `json:"sig_preimage"`
	Enc         hexBytes `json:"enc"`
	Enc2        hexBytes `json:"enc2"`
	Envelope    hexBytes `json:"envelope"`
	EnvDigest   hexBytes `json:"env_digest"`
	AckKey      hexBytes `json:"ack_key"`
	Negatives   []struct {
		Name     string   `json:"name"`
		Envelope hexBytes `json:"envelope"`
		Reason   string   `json:"reason"`
	} `json:"negatives"`
	BodyNegatives []struct {
		Name      string   `json:"name"`
		Body      hexBytes `json:"body"`
		RefusedBy string   `json:"refused_by"`
	} `json:"body_negatives"`
}

func TestSEALED_PREVIEW_1(t *testing.T) {
	const vid = "SEALED-PREVIEW-1"
	var v vecSealedPreview
	readVector(t, fileSealedPreview, &v)
	kp, senderPub := v.keys(t, vid)
	ixKey := v.RecipientIX.key(t, vid, v.Sender.AID)

	info, err := HPKEInfo(v.Recipient.AID, SuiteX25519, kp.Public.KID)
	if err != nil || !bytes.Equal(info, v.HPKEInfo) {
		t.Fatalf("hpke info %x, file %x (%v)", info, v.HPKEInfo, err)
	}
	ixInfo, err := IXInfo(v.Recipient.AID, SuiteX25519, ixKey.KID())
	if err != nil || !bytes.Equal(ixInfo, v.IXInfo) {
		t.Fatalf("layer-2 info %x, file %x (%v)", ixInfo, v.IXInfo, err)
	}
	o, err := Open(v.Envelope, v.Recipient.AID, StaticKeyRing{kp}, ixKeys{ixKey})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	t.Run("a one-shot envelope in two layers", func(t *testing.T) {
		// CORE-K5, CUX-E1: outer key 8 present, equal to the inner exp, which is ts + 60 s; the
		// second layer to the requester's interaction key in this interaction.
		if o.Outer.Exp == nil || *o.Outer.Exp != o.Inner.Exp || o.Inner.Exp != o.Inner.TS+60_000 ||
			o.Inner.Exp != v.Inner.Exp || o.Inner.TS != v.Inner.TS {
			t.Fatalf("outer exp %v, inner ts %d exp %d", o.Outer.Exp, o.Inner.TS, o.Inner.Exp)
		}
		if o.Layers != 2 || !bytes.Equal(o.IKID, v.RecipientIX.KID) || !bytes.Equal(o.Outer.Enc, v.Enc) {
			t.Fatalf("layers %d, ikid %x", o.Layers, o.IKID)
		}
		d, err := EnvDigest(v.Envelope)
		if err != nil || !bytes.Equal(d[:], v.EnvDigest) {
			t.Fatalf("env_digest %x, file %x (%v)", d, v.EnvDigest, err)
		}
		if !bytes.Equal(o.AckKey[:], v.AckKey) {
			t.Fatalf("ack_key %x, file %x", o.AckKey, v.AckKey)
		}
		_, inner := openBoth(t, v.Envelope, kp, ixKey)
		if !bytes.Equal(inner, v.InnerCBOR) {
			t.Fatal("the second layer does not hold the file's inner")
		}
	})
	t.Run("the inner of a preview frame", func(t *testing.T) {
		// No KEL, notice, key set or grant (keys 10, 11, 12, 14); the sender's interaction key
		// (key 15).
		in, want := o.Inner, v.Inner
		if in.From != want.From || in.From != v.Sender.AID || in.KeyStateSeq != want.KeyStateSeq || in.To != want.To ||
			in.Type != "anet.message/1" || in.Type != want.Type || in.IX != want.IX || in.IX != v.RecipientIX.IX ||
			!bytes.Equal(in.MID, want.MID) || !bytes.Equal(in.Body, want.Body) || !bytes.Equal(in.Sig, want.Sig) {
			t.Fatalf("opened inner %+v\nfile %+v", in, want)
		}
		if in.KEL != nil || in.Notices != nil || in.Keys != nil || in.Grant != nil || len(in.Ext) != 0 {
			t.Fatal("a preview frame's inner carries key 10, 11, 12, 14 or an extension")
		}
		if in.RK == nil || in.RK.Suite != want.RK.Suite || !bytes.Equal(in.RK.Pub, want.RK.Pub) {
			t.Fatalf("rk %+v", in.RK)
		}
		fields, err := decodeFields(v.InnerCBOR)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []uint64{keyKEL, keyNotice, keyKeys, keyGrant} {
			if _, has := fields[k]; has {
				t.Fatalf("inner key %d present", k)
			}
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
		if err := VerifyInnerSig(&o.Inner, o.Preimage, kel, v.Inner.TS+minuteMS/2); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the body is a preview frame", func(t *testing.T) {
		m, err := delegation.UnmarshalChatMsg(o.Inner.Body)
		if err != nil {
			t.Fatalf("the body does not decode as a ChatMsg: %v", err)
		}
		if err := delegation.ValidatePreview(m); err != nil {
			t.Fatalf("the frame is refused: %v", err)
		}
		f := v.Frame
		if m.Kind != f.Kind || m.Body != f.Body || m.StreamSeq != f.StreamSeq || m.StreamAtMS != f.StreamAtMS ||
			m.ReasoningBody != f.ReasoningBody || m.ReasoningStreamAtMS != f.ReasoningAtMS || m.MsgID != f.MsgID ||
			m.Omitted != f.Omitted || m.ReasoningOmitted != f.ReasoningOmitted || m.Answers != f.Answers ||
			m.Attachments != nil || m.Metadata != nil {
			t.Fatalf("frame %+v\nfile %+v", m, f)
		}
		if again, err := m.Marshal(); err != nil || !bytes.Equal(again, o.Inner.Body) {
			t.Fatal("Go encodes the frame differently from the independent encoder")
		}
	})
	t.Run("negatives", func(t *testing.T) {
		if len(v.Negatives) != 2 {
			t.Fatalf("%d negatives, want 2", len(v.Negatives))
		}
		for _, n := range v.Negatives {
			_, err := Open(n.Envelope, v.Recipient.AID, StaticKeyRing{kp}, ixKeys{ixKey})
			wantOpenFails(t, err, n.Reason, true)
		}
		if len(v.BodyNegatives) < 6 {
			t.Fatalf("%d body negatives", len(v.BodyNegatives))
		}
		for _, n := range v.BodyNegatives {
			m, err := delegation.UnmarshalChatMsg(n.Body)
			switch n.RefusedBy {
			case "decode":
				if !errors.Is(err, delegation.ErrBody) {
					t.Errorf("%s: want ErrBody when it decodes, got %v", n.Name, err)
				}
			case "validate":
				if err != nil {
					t.Fatalf("%s: does not decode: %v", n.Name, err)
				}
				if err := delegation.ValidatePreview(m); !errors.Is(err, delegation.ErrBody) {
					t.Errorf("%s: want ErrBody from ValidatePreview, got %v", n.Name, err)
				}
			default:
				t.Fatalf("%s: refused_by %q", n.Name, n.RefusedBy)
			}
		}
	})
}
