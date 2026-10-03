package evidence_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/delegation"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/payment"
	"github.com/ANetResearch/ANetCore/tsir"
)

// The golden vectors EV2-1 and REVIEW-2 (core §5.2) are written by golden/py/gen_v016.py, an
// implementation that shares nothing with this package; golden-xcheck regenerates them byte for
// byte. These tests reproduce every value from the same inputs with the code under test.

func loadVector(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

// hexBytes is a JSON hex string.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	out, err := hex.DecodeString(s)
	*h = out
	return err
}

type negative struct {
	Name              string   `json:"name"`
	Note              string   `json:"note"`
	Wire              hexBytes `json:"wire"`
	ReviewWire        hexBytes `json:"review_wire"`
	AttestationWire   hexBytes `json:"attestation_wire"`
	AuthorizationWire hexBytes `json:"authorization_wire"`
	VerifyAt          int64    `json:"verify_at"`
	Refused           string   `json:"refused"`
}

// refusal maps a vector's "refused" to the error it names.
var refusal = map[string]error{
	"decode": evidence.ErrMalformed, "signature": evidence.ErrSignature, "signer": evidence.ErrSigner,
	"rating": evidence.ErrRating, "comment": evidence.ErrComment,
}

type ev2Vector struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Labels      map[string]string `json:"labels"`
	Task        struct {
		IX            string   `json:"ix"`
		Nonce         string   `json:"nonce"`
		NonceSeed     string   `json:"nonce_seed"`
		RequesterAID  string   `json:"requester_aid"`
		RSalt         hexBytes `json:"rsalt"`
		ReviewKeySeed hexBytes `json:"review_key_seed"`
		ReviewKey     hexBytes `json:"review_key"`
		TaskDoc       hexBytes `json:"taskdoc"`
		RequestCID    string   `json:"request_cid"`
		Deliverable   hexBytes `json:"deliverable"`
		ResultCID     string   `json:"result_cid"`
		CompletedDay  uint64   `json:"completed_day"`
	} `json:"task"`
	Provider struct {
		AID string   `json:"aid"`
		KEL hexBytes `json:"kel"`
	} `json:"provider"`
	IXCommit        preimageHash `json:"ix_commit"`
	RequesterCommit preimageHash `json:"requester_commit"`
	PayBind         struct {
		Preimage hexBytes `json:"preimage"`
		Hex      string   `json:"hex"`
	} `json:"pay_bind"`
	SettleGuard struct {
		Payer    string   `json:"payer"`
		PayBind  string   `json:"pay_bind"`
		Preimage hexBytes `json:"preimage"`
		Hash     hexBytes `json:"hash"`
	} `json:"settle_guard"`
	Receipt struct {
		Body     hexBytes `json:"body"`
		BodyCID  string   `json:"body_cid"`
		Sig      hexBytes `json:"sig"`
		Envelope struct {
			SignerAID   string `json:"signer_aid"`
			KeyStateSeq uint64 `json:"key_state_seq"`
			Alg         int    `json:"alg"`
		} `json:"envelope"`
		Wire     hexBytes `json:"wire"`
		VerifyAt uint64   `json:"verify_at"`
	} `json:"receipt"`
	Negatives  []negative `json:"negatives"`
	NULRefused []struct {
		IX    string `json:"ix"`
		Nonce string `json:"nonce"`
		Note  string `json:"note"`
	} `json:"nul_refused"`
}

type preimageHash struct {
	Preimage hexBytes `json:"preimage"`
	Hash     hexBytes `json:"hash"`
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestEV2_1(t *testing.T) {
	var v ev2Vector
	loadVector(t, "vec-ev2-1.json", &v)
	tk := v.Task
	z := []byte{0}

	// L27, L28, L34, L33: preimages and hashes.
	if want := cat([]byte(v.Labels["ix_commit"]), z, []byte(tk.IX), z, []byte(tk.Nonce)); !bytes.Equal(v.IXCommit.Preimage, want) {
		t.Errorf("L27 preimage")
	}
	if got, err := evidence.IXCommit(tk.IX, tk.Nonce); err != nil || !bytes.Equal(got, v.IXCommit.Hash) {
		t.Errorf("ix_commit %x, want %x (%v)", got, []byte(v.IXCommit.Hash), err)
	}
	if want := cat([]byte(v.Labels["requester_commit"]), z, []byte(tk.RequesterAID), z, tk.RSalt); !bytes.Equal(v.RequesterCommit.Preimage, want) {
		t.Errorf("L28 preimage")
	}
	if got, err := evidence.RequesterCommit(tk.RequesterAID, tk.RSalt); err != nil || !bytes.Equal(got, v.RequesterCommit.Hash) {
		t.Errorf("requester_commit %x, want %x (%v)", got, []byte(v.RequesterCommit.Hash), err)
	}
	pb := sha256.Sum256(cat([]byte(v.Labels["pay_bind"]), z, []byte(tk.IX), z, []byte(tk.Nonce)))
	if !bytes.Equal(v.PayBind.Preimage, cat([]byte(v.Labels["pay_bind"]), z, []byte(tk.IX), z, []byte(tk.Nonce))) || hex.EncodeToString(pb[:]) != v.PayBind.Hex {
		t.Errorf("PayBind (L34) of the vector does not match its formula")
	}
	if v.SettleGuard.PayBind != v.PayBind.Hex || v.SettleGuard.Payer != tk.RequesterAID {
		t.Errorf("settle guard inputs")
	}
	if want := cat([]byte(v.Labels["settle_guard"]), z, []byte(v.SettleGuard.Payer), z, []byte(v.SettleGuard.PayBind)); !bytes.Equal(v.SettleGuard.Preimage, want) {
		t.Errorf("L33 preimage")
	}
	if got, err := evidence.SettleGuard(v.SettleGuard.Payer, v.SettleGuard.PayBind); err != nil || !bytes.Equal(got, v.SettleGuard.Hash) {
		t.Errorf("settle guard %x, want %x (%v)", got, []byte(v.SettleGuard.Hash), err)
	}

	// The task binding and the TaskDoc it rides in.
	if pub := ed25519.NewKeyFromSeed(tk.ReviewKeySeed).Public().(ed25519.PublicKey); !bytes.Equal(pub, tk.ReviewKey) {
		t.Fatalf("review key does not derive from its seed")
	}
	binding := &delegation.TaskBinding{Nonce: tk.Nonce, RequesterCommit: v.RequesterCommit.Hash, ReviewKey: tk.ReviewKey}
	ctx, err := binding.Contexts()
	if err != nil {
		t.Fatal(err)
	}
	doc := tsir.TaskDoc{Version: tsir.VersionPair{Major: 1},
		Tasks: []tsir.Task{{Intent: tsir.Intent{Summary: "caption", Body: "caption the image"}, Contexts: ctx}}}
	if raw, err := coredet.Marshal(doc); err != nil || !bytes.Equal(raw, tk.TaskDoc) {
		t.Fatalf("the TaskDoc with the binding contexts:\n got  %x\n want %x", raw, []byte(tk.TaskDoc))
	}
	if anetcid.MustSum(tk.TaskDoc) != tk.RequestCID || anetcid.MustSum(tk.Deliverable) != tk.ResultCID {
		t.Fatalf("request or result CID")
	}
	if err := delegation.CheckTaskBinding(&doc); err != nil {
		t.Fatalf("the vector's TaskDoc carries a well-formed binding: %v", err)
	}

	// The receipt: body, signature by the conformance identity, wire.
	c := identity.SuiteController()
	kel, err := identity.UnmarshalKEL(v.Provider.KEL)
	if err != nil {
		t.Fatal(err)
	}
	if mine, _ := identity.MarshalKEL(c.KEL()); !bytes.Equal(mine, v.Provider.KEL) || v.Provider.AID != c.AID() {
		t.Fatalf("the provider is the conformance identity")
	}
	body := &evidence.ReceiptBody{IXCommit: v.IXCommit.Hash, RequesterCommit: v.RequesterCommit.Hash, ReviewKey: tk.ReviewKey,
		RequestCID: tk.RequestCID, ResultCID: tk.ResultCID, CompletedDay: tk.CompletedDay}
	w, err := body.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Body, v.Receipt.Body) {
		t.Fatalf("receipt body\n got  %x\n want %x", w.Body, []byte(v.Receipt.Body))
	}
	if !bytes.Equal(w.Env.Sig, v.Receipt.Sig) || w.Env.SignerAID != v.Receipt.Envelope.SignerAID ||
		w.Env.KeyStateSeq != v.Receipt.Envelope.KeyStateSeq || w.Env.Alg != v.Receipt.Envelope.Alg {
		t.Fatalf("receipt envelope %+v", w.Env)
	}
	if raw, err := w.Marshal(); err != nil || !bytes.Equal(raw, v.Receipt.Wire) {
		t.Fatalf("receipt wire\n got  %x\n want %x", raw, []byte(v.Receipt.Wire))
	}
	if cid, _ := w.CID(); cid != v.Receipt.BodyCID {
		t.Fatalf("receipt_cid %s, want %s", cid, v.Receipt.BodyCID)
	}
	back, err := evidence.UnmarshalReceiptWire(v.Receipt.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := back.Verify(kel, v.Receipt.VerifyAt); err != nil {
		t.Fatalf("the vector's receipt must verify: %v", err)
	}
	// The requester's check of the completion that carries it.
	rr := &delegation.ResultResp{Status: delegation.StatusDone, Deliverable: tk.Deliverable, Receipt: v.Receipt.Wire}
	if _, err := delegation.VerifyResultForRequest(rr, kel, delegation.ResultCheck{IX: tk.IX, Provider: v.Provider.AID,
		TaskDoc: tk.TaskDoc, DelegatedDay: tk.CompletedDay, Today: tk.CompletedDay}, v.Receipt.VerifyAt); err != nil {
		t.Fatalf("the requester's check of the vector's completion: %v", err)
	}

	if len(v.Negatives) == 0 {
		t.Fatal("no negatives")
	}
	for _, n := range v.Negatives {
		t.Run(n.Name, func(t *testing.T) {
			want := refusal[n.Refused]
			if want == nil {
				t.Fatalf("unknown refusal %q", n.Refused)
			}
			if len(n.AuthorizationWire) > 0 { // SI-81
				a, err := payment.UnmarshalAuthorization(n.AuthorizationWire)
				if err != nil {
					t.Fatalf("the authorization decodes; it is its signature that must fail: %v", err)
				}
				if err := a.Verify(kel, n.VerifyAt); err == nil || !bytes.Equal(a.Envelope.Sig, v.Receipt.Sig) {
					t.Fatalf("a receipt's signature authorized a payment (%v)", err)
				}
				return
			}
			w, err := evidence.UnmarshalReceiptWire(n.Wire)
			if err == nil {
				_, err = w.Verify(kel, v.Receipt.VerifyAt)
			}
			if !errors.Is(err, want) {
				t.Fatalf("%s: want %v, got %v", n.Note, want, err)
			}
		})
	}
	if len(v.NULRefused) != 2 {
		t.Fatal("the two NUL cases")
	}
	for _, n := range v.NULRefused {
		if _, err := evidence.IXCommit(n.IX, n.Nonce); !errors.Is(err, evidence.ErrNUL) {
			t.Errorf("IXCommit(%q, %q): want ErrNUL, got %v", n.IX, n.Nonce, err)
		}
	}
}

type review2Vector struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Labels      map[string]string `json:"labels"`
	Receipt     struct {
		Wire        hexBytes `json:"wire"`
		BodyCID     string   `json:"body_cid"`
		ProviderKEL hexBytes `json:"provider_kel"`
	} `json:"receipt"`
	Review struct {
		KeySeed   hexBytes `json:"key_seed"`
		Pub       hexBytes `json:"pub"`
		Body      hexBytes `json:"body"`
		ReviewCID string   `json:"review_cid"`
		Sig       hexBytes `json:"sig"`
		Wire      hexBytes `json:"wire"`
	} `json:"review"`
	Tag struct {
		Key         hexBytes `json:"key"`
		ReviewerAID string   `json:"reviewer_aid"`
		SubjectAID  string   `json:"subject_aid"`
		Message     hexBytes `json:"message"`
		Tag         hexBytes `json:"tag"`
	} `json:"tag"`
	Hub struct {
		AID    string   `json:"aid"`
		Labels []string `json:"labels"`
		KEL    hexBytes `json:"kel"`
	} `json:"hub"`
	Attestation struct {
		Body     hexBytes `json:"body"`
		Sig      hexBytes `json:"sig"`
		Wire     hexBytes `json:"wire"`
		VerifyAt uint64   `json:"verify_at"`
	} `json:"attestation"`
	Negatives []negative `json:"negatives"`
}

func TestREVIEW_2(t *testing.T) {
	var v review2Vector
	loadVector(t, "vec-review-2.json", &v)
	var ev2 ev2Vector
	loadVector(t, "vec-ev2-1.json", &ev2)
	if !bytes.Equal(v.Receipt.Wire, ev2.Receipt.Wire) || !bytes.Equal(v.Receipt.ProviderKEL, ev2.Provider.KEL) {
		t.Fatal("REVIEW-2 rates the EV2-1 receipt")
	}
	receipt, err := evidence.UnmarshalReceiptWire(v.Receipt.Wire)
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := receipt.Open()
	providerKEL, err := identity.UnmarshalKEL(v.Receipt.ProviderKEL)
	if err != nil {
		t.Fatal(err)
	}

	// L30: the review signed by the one-time key.
	var fields map[uint64]any
	if err := coredet.Unmarshal(v.Review.Body, &fields); err != nil {
		t.Fatal(err)
	}
	body := &evidence.ReviewBody{ReceiptCID: v.Receipt.BodyCID, Subject: rc.Provider, Rating: 5, Comment: fields[4].(string), CreatedDay: rc.CompletedDay + 1}
	key := ed25519.NewKeyFromSeed(v.Review.KeySeed)
	rv, err := body.Sign(key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rv.Body, v.Review.Body) || !bytes.Equal(rv.Sig, v.Review.Sig) || !bytes.Equal(rv.Pub, v.Review.Pub) {
		t.Fatalf("review\n got  %x\n want %x", rv.Body, []byte(v.Review.Body))
	}
	if raw, err := rv.Marshal(); err != nil || !bytes.Equal(raw, v.Review.Wire) {
		t.Fatalf("review wire\n got  %x\n want %x", raw, []byte(v.Review.Wire))
	}
	if cid, _ := rv.CID(); cid != v.Review.ReviewCID {
		t.Fatalf("review_cid %s, want %s", cid, v.Review.ReviewCID)
	}
	if !bytes.Equal(v.Review.Pub, rc.ReviewKey) {
		t.Fatal("the review key is the receipt's review_key")
	}
	if _, _, err := evidence.CheckV2(receipt, rv, providerKEL); err != nil {
		t.Fatalf("the vector's receipt and review must interlock: %v", err)
	}

	// L31: the tag.
	if want := cat([]byte(v.Labels["tag"]), []byte{0}, []byte(v.Tag.ReviewerAID), []byte{0}, []byte(v.Tag.SubjectAID)); !bytes.Equal(v.Tag.Message, want) {
		t.Errorf("L31 message")
	}
	if v.Tag.ReviewerAID != ev2.Task.RequesterAID || v.Tag.SubjectAID != rc.Provider {
		t.Errorf("the tag is the EV2-1 requester's for the provider")
	}
	tag, err := evidence.ReviewTag(v.Tag.Key, v.Tag.ReviewerAID, v.Tag.SubjectAID)
	if err != nil || !bytes.Equal(tag, v.Tag.Tag) {
		t.Fatalf("tag %x, want %x (%v)", tag, []byte(v.Tag.Tag), err)
	}

	// L32: the attestation, signed by the hub of the labels.
	hubKEL, err := identity.UnmarshalKEL(v.Hub.KEL)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Hub.Labels) != 2 || hubKEL[0].EventID != v.Hub.AID {
		t.Fatal("hub identity")
	}
	k0 := sha256.Sum256([]byte(v.Hub.Labels[0]))
	att := &evidence.ReviewAttBody{ReviewCID: v.Review.ReviewCID, ReceiptCID: v.Receipt.BodyCID, Subject: rc.Provider, Tag: tag,
		TagKeyID: 1, Day: rc.CompletedDay + 2, Hub: v.Hub.AID}
	attBody, err := att.Marshal()
	if err != nil || !bytes.Equal(attBody, v.Attestation.Body) {
		t.Fatalf("attestation body\n got  %x\n want %x (%v)", attBody, []byte(v.Attestation.Body), err)
	}
	if sig := ed25519.Sign(ed25519.NewKeyFromSeed(k0[:]), attBody); !bytes.Equal(sig, v.Attestation.Sig) {
		t.Fatal("attestation signature")
	}
	aw, err := evidence.UnmarshalReviewAttWire(v.Attestation.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := aw.Marshal(); err != nil || !bytes.Equal(raw, v.Attestation.Wire) {
		t.Fatal("attestation wire does not re-encode to itself")
	}
	if _, err := aw.Verify(hubKEL, v.Attestation.VerifyAt); err != nil {
		t.Fatalf("the vector's attestation must verify: %v", err)
	}

	if len(v.Negatives) == 0 {
		t.Fatal("no negatives")
	}
	for _, n := range v.Negatives {
		t.Run(n.Name, func(t *testing.T) {
			want := refusal[n.Refused]
			if want == nil {
				t.Fatalf("unknown refusal %q", n.Refused)
			}
			var err error
			switch {
			case len(n.ReviewWire) > 0:
				var w *evidence.ReviewWire
				if w, err = evidence.UnmarshalReviewWire(n.ReviewWire); err == nil {
					_, err = w.Verify(rc.ReviewKey)
				}
			case len(n.AttestationWire) > 0:
				var w *evidence.ReviewAttWire
				if w, err = evidence.UnmarshalReviewAttWire(n.AttestationWire); err == nil {
					_, err = w.Verify(hubKEL, v.Attestation.VerifyAt)
				}
			default:
				t.Fatal("a negative names a review or an attestation")
			}
			if !errors.Is(err, want) {
				t.Fatalf("%s: want %v, got %v", n.Note, want, err)
			}
		})
	}
}
