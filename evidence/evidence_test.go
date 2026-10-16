package evidence_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
	"github.com/ANetResearch/ANetCore/aobj"
	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/evidence"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
)

// day is the completed_day of the test receipts: 2026-01-01.
const day = 20454

func seed32(label string) []byte {
	s := sha256.Sum256([]byte("anet-test/evidence/" + label))
	return s[:]
}

func incept(t testing.TB) *identity.Controller {
	t.Helper()
	c, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// reviewKey is the one-time review key of the test task.
func reviewKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed32("review")) }

func testBody(t testing.TB, provider string) *evidence.ReceiptBody {
	t.Helper()
	ixc, err := evidence.IXCommit("ix-1", "bm9uY2Utb2YtdGFzaw")
	if err != nil {
		t.Fatal(err)
	}
	rqc, err := evidence.RequesterCommit("bafyreirequester", seed32("rsalt"))
	if err != nil {
		t.Fatal(err)
	}
	return &evidence.ReceiptBody{
		IXCommit: ixc, RequesterCommit: rqc, ReviewKey: reviewKey().Public().(ed25519.PublicKey),
		Provider: provider, RequestCID: anetcid.MustSum([]byte("request")),
		ResultCID: anetcid.MustSum([]byte("result")), CompletedDay: day,
	}
}

func signReceipt(t testing.TB, c *identity.Controller, b *evidence.ReceiptBody) *evidence.ReceiptWire {
	t.Helper()
	w, err := b.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func mustMarshal(t testing.TB, v interface{ Marshal() ([]byte, error) }) []byte {
	t.Helper()
	b, err := v.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAReceiptSurvivesTheWireAndVerifies(t *testing.T) {
	p := incept(t)
	w := signReceipt(t, p, testBody(t, ""))
	raw := mustMarshal(t, w)
	back, err := evidence.UnmarshalReceiptWire(raw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := back.Verify(p.KEL(), day*evidence.DayMS)
	if err != nil {
		t.Fatalf("a genuine receipt must verify: %v", err)
	}
	if body.Type != evidence.ReceiptType || body.Provider != p.AID() {
		t.Fatalf("body %+v: the type tag and the signer as provider are filled in", body)
	}
	// receipt_cid is the CID of the body bytes, the same however it is reached (CORE-K12).
	c1, _ := back.CID()
	c2, _ := body.CID()
	if c1 != c2 || c1 != anetcid.MustSum(back.Body) {
		t.Fatalf("receipt CIDs disagree: %s %s", c1, c2)
	}
	// The body bytes start with key 0 and the type tag: class A (CORE-L1).
	want, _ := coredet.Marshal(evidence.ReceiptType)
	if !bytes.HasPrefix(back.Body[1:], append([]byte{0x00}, want...)) {
		t.Fatalf("the body does not lead with key 0 = %q: %x", evidence.ReceiptType, back.Body[:24])
	}
}

func TestOnlyTheProviderSignsItsReceipt(t *testing.T) {
	p, other := incept(t), incept(t)
	if _, err := testBody(t, p.AID()).Sign(other); !errors.Is(err, evidence.ErrSigner) {
		t.Fatalf("signing another provider's receipt: want ErrSigner, got %v", err)
	}
	// An envelope moved to another signer: the signature may even verify under that signer's KEL,
	// but the receipt names a provider that did not sign it.
	w := signReceipt(t, other, testBody(t, other.AID()))
	body, _ := w.Open()
	body.Provider = p.AID()
	raw, _ := body.Marshal()
	sig, seq := other.Sign(raw)
	forged := &evidence.ReceiptWire{Body: raw, Env: &aobj.Envelope{SignerAID: other.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}}
	if _, err := forged.Verify(other.KEL(), day*evidence.DayMS); !errors.Is(err, evidence.ErrSigner) {
		t.Fatalf("signer is not the provider: want ErrSigner, got %v", err)
	}
	// Another KEL than the signer's.
	w = signReceipt(t, p, testBody(t, ""))
	if _, err := w.Verify(other.KEL(), day*evidence.DayMS); !errors.Is(err, evidence.ErrSignature) {
		t.Fatalf("verified against the wrong KEL: want ErrSignature, got %v", err)
	}
	// One byte of the body changed after signing.
	tampered := *w
	tampered.Body = bytes.Clone(w.Body)
	tampered.Body[len(tampered.Body)-1] ^= 1
	if _, err := tampered.Verify(p.KEL(), day*evidence.DayMS); !errors.Is(err, evidence.ErrSignature) {
		t.Fatalf("tampered body: want ErrSignature, got %v", err)
	}
}

func TestAReceiptSignedWithARetiredKeyIsRefusedFromItsRetirement(t *testing.T) {
	p := incept(t)
	w := signReceipt(t, p, testBody(t, ""))
	rotateAt := uint64(day)*evidence.DayMS + 3_600_000 // one hour into the receipt's day
	if err := identitytest.Rotate(p, rotateAt); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Verify(p.KEL(), rotateAt-1); err != nil {
		t.Errorf("before the rotation: must verify, got %v", err)
	}
	if _, err := w.Verify(p.KEL(), rotateAt); !errors.Is(err, evidence.ErrSignature) || !strings.Contains(err.Error(), "REVOKED_KEY") {
		t.Errorf("at the rotation: want REVOKED_KEY, got %v", err)
	}
}

// Every way of handing a decoder something that is not exactly a receipt is refused, with
// ErrMalformed (CORE-E2, CORE-E3, CORE-E4).
func TestTheReceiptDecodersAreStrict(t *testing.T) {
	p := incept(t)
	w := signReceipt(t, p, testBody(t, ""))
	raw := mustMarshal(t, w)
	var body map[uint64]any
	if err := coredet.Unmarshal(w.Body, &body); err != nil {
		t.Fatal(err)
	}
	reBody := func(edit func(m map[uint64]any)) []byte {
		m := map[uint64]any{}
		for k, v := range body {
			m[k] = v
		}
		edit(m)
		b, err := coredet.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := coredet.Marshal(map[uint64]any{1: b, 2: w.Env})
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	cases := map[string][]byte{
		"empty":                   nil,
		"null":                    {0xf6},
		"trailing byte":           append(bytes.Clone(raw), 0x00),
		"unregistered wire key 3": mustCBOR(t, map[uint64]any{1: w.Body, 2: w.Env, 3: 1}),
		"wire key 64":             mustCBOR(t, map[uint64]any{1: w.Body, 2: w.Env, 64: 1}),
		"no envelope":             mustCBOR(t, map[uint64]any{1: w.Body}),
		"no body":                 mustCBOR(t, map[uint64]any{2: w.Env}),
		"unregistered body key 8": reBody(func(m map[uint64]any) { m[8] = 1 }),
		"no type tag":             reBody(func(m map[uint64]any) { delete(m, 0) }),
		"type tag of a review":    reBody(func(m map[uint64]any) { m[0] = evidence.ReviewType }),
		"type tag v1":             reBody(func(m map[uint64]any) { m[0] = "anet.receipt/1" }),
		"ix_commit 31 bytes":      reBody(func(m map[uint64]any) { m[1] = make([]byte, 31) }),
		"requester_commit absent": reBody(func(m map[uint64]any) { delete(m, 2) }),
		"review_key 33 bytes":     reBody(func(m map[uint64]any) { m[3] = make([]byte, 33) }),
		"provider empty":          reBody(func(m map[uint64]any) { m[4] = "" }),
		"provider with U+0000":    reBody(func(m map[uint64]any) { m[4] = "a\x00b" }),
		"request_cid absent":      reBody(func(m map[uint64]any) { delete(m, 5) }),
		"completed_day negative":  reBody(func(m map[uint64]any) { m[7] = -1 }),
		"completed_day a string":  reBody(func(m map[uint64]any) { m[7] = "20454" }),
	}
	// A map the encoder would never write: the same two entries, key 2 before key 1.
	swapped := append([]byte{0xa2, 0x02}, mustCBOR(t, w.Env)...)
	swapped = append(append(swapped, 0x01), mustCBOR(t, w.Body)...)
	cases["keys out of order"] = swapped
	for name, b := range cases {
		if _, err := evidence.UnmarshalReceiptWire(b); !errors.Is(err, evidence.ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
	if _, err := evidence.UnmarshalReceiptWire(raw); err != nil {
		t.Fatalf("the genuine bytes: %v", err)
	}
	// An envelope that names a preimage reference: a second byte form of one signature.
	env := *w.Env
	env.PreimageRef = "bafyref"
	if _, err := evidence.UnmarshalReceiptWire(mustCBOR(t, map[uint64]any{1: w.Body, 2: env})); !errors.Is(err, evidence.ErrMalformed) {
		t.Errorf("preimage reference: want ErrMalformed, got %v", err)
	}
	// The encoder refuses the same shapes it would refuse to read.
	bad := testBody(t, p.AID())
	bad.IXCommit = bad.IXCommit[:31]
	if _, err := bad.Marshal(); !errors.Is(err, evidence.ErrMalformed) {
		t.Errorf("marshal a short ix_commit: want ErrMalformed, got %v", err)
	}
	bad = testBody(t, p.AID())
	bad.Type = evidence.ReviewType
	if _, err := bad.Sign(p); !errors.Is(err, evidence.ErrMalformed) {
		t.Errorf("sign a body with another type tag: want ErrMalformed, got %v", err)
	}
}

func mustCBOR(t testing.TB, v any) []byte {
	t.Helper()
	b, err := coredet.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testReview(t testing.TB, w *evidence.ReceiptWire) *evidence.ReviewBody {
	t.Helper()
	body, err := w.Open()
	if err != nil {
		t.Fatal(err)
	}
	cid, err := w.CID()
	if err != nil {
		t.Fatal(err)
	}
	return &evidence.ReviewBody{ReceiptCID: cid, Subject: body.Provider, Rating: 5, Comment: "清楚、准时", CreatedDay: day + 1}
}

func TestAReviewIsSignedByTheReceiptsReviewKeyOnly(t *testing.T) {
	p := incept(t)
	w := signReceipt(t, p, testBody(t, ""))
	rv, err := testReview(t, w).Sign(reviewKey())
	if err != nil {
		t.Fatal(err)
	}
	raw := mustMarshal(t, rv)
	back, err := evidence.UnmarshalReviewWire(raw)
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := w.Open()
	body, err := back.Verify(rc.ReviewKey)
	if err != nil || body.Rating != 5 || body.Type != evidence.ReviewType {
		t.Fatalf("a genuine review must verify: %+v, %v", body, err)
	}
	// Signed by another key, carrying that key: verifies on its own, not as this receipt's review.
	other, _ := testReview(t, w).Sign(ed25519.NewKeyFromSeed(seed32("other")))
	if _, err := other.Verify(rc.ReviewKey); !errors.Is(err, evidence.ErrSigner) {
		t.Fatalf("a review under another key: want ErrSigner, got %v", err)
	}
	// Carrying the right key, signed by another.
	swapped := *other
	swapped.Pub = bytes.Clone(rc.ReviewKey)
	if _, err := swapped.Verify(rc.ReviewKey); !errors.Is(err, evidence.ErrSignature) {
		t.Fatalf("a signature by another key: want ErrSignature, got %v", err)
	}
}

func TestReviewRatingAndCommentBounds(t *testing.T) {
	w := signReceipt(t, incept(t), testBody(t, ""))
	for _, r := range []uint64{0, 6, 255} {
		b := testReview(t, w)
		b.Rating = r
		if _, err := b.Sign(reviewKey()); !errors.Is(err, evidence.ErrRating) {
			t.Errorf("rating %d: want ErrRating, got %v", r, err)
		}
	}
	b := testReview(t, w)
	b.Comment = strings.Repeat("评", evidence.MaxCommentChars) // 280 characters, 840 bytes
	if _, err := b.Sign(reviewKey()); err != nil {
		t.Errorf("280 characters must be accepted (characters, not bytes): %v", err)
	}
	b.Comment += "!"
	if _, err := b.Sign(reviewKey()); !errors.Is(err, evidence.ErrComment) {
		t.Errorf("281 characters: want ErrComment, got %v", err)
	}
	// The decoder says the same about bytes it is handed.
	good, _ := testReview(t, w).Sign(reviewKey())
	var m map[uint64]any
	_ = coredet.Unmarshal(good.Body, &m)
	m[3] = 9
	body := mustCBOR(t, m)
	key := reviewKey()
	bad := mustCBOR(t, map[uint64]any{1: body, 2: key.Public(), 3: ed25519.Sign(key, body)})
	if _, err := evidence.UnmarshalReviewWire(bad); !errors.Is(err, evidence.ErrRating) {
		t.Errorf("decode rating 9: want ErrRating, got %v", err)
	}
	// An empty comment is absent, never an empty key 4: one byte form.
	m[3] = 5
	m[4] = ""
	body = mustCBOR(t, m)
	bad = mustCBOR(t, map[uint64]any{1: body, 2: key.Public(), 3: ed25519.Sign(key, body)})
	if _, err := evidence.UnmarshalReviewWire(bad); !errors.Is(err, evidence.ErrMalformed) {
		t.Errorf("an empty key 4: want ErrMalformed, got %v", err)
	}
}

func TestTheReviewDecodersAreStrict(t *testing.T) {
	w := signReceipt(t, incept(t), testBody(t, ""))
	rv, _ := testReview(t, w).Sign(reviewKey())
	cases := map[string][]byte{
		"key 4":           mustCBOR(t, map[uint64]any{1: rv.Body, 2: rv.Pub, 3: rv.Sig, 4: 0}),
		"pub 31 bytes":    mustCBOR(t, map[uint64]any{1: rv.Body, 2: rv.Pub[:31], 3: rv.Sig}),
		"sig 63 bytes":    mustCBOR(t, map[uint64]any{1: rv.Body, 2: rv.Pub, 3: rv.Sig[:63]}),
		"no sig":          mustCBOR(t, map[uint64]any{1: rv.Body, 2: rv.Pub}),
		"body is a map":   mustCBOR(t, map[uint64]any{1: map[uint64]any{0: evidence.ReviewType}, 2: rv.Pub, 3: rv.Sig}),
		"receipt as body": mustCBOR(t, map[uint64]any{1: w.Body, 2: rv.Pub, 3: rv.Sig}),
	}
	for name, b := range cases {
		if _, err := evidence.UnmarshalReviewWire(b); !errors.Is(err, evidence.ErrMalformed) {
			t.Errorf("%s: want ErrMalformed, got %v", name, err)
		}
	}
}

func TestAnAttestationIsTheHubsAndOnlyTheHubs(t *testing.T) {
	hub, other := incept(t), incept(t)
	tag, err := evidence.ReviewTag(seed32("tag-key"), "bafyreirequester", "bafyreiprovider")
	if err != nil {
		t.Fatal(err)
	}
	body := &evidence.ReviewAttBody{ReviewCID: "bafyreview", ReceiptCID: "bafyreceipt", Subject: "bafyreiprovider",
		Tag: tag, TagKeyID: 1, Day: day + 2}
	att, err := body.Sign(hub)
	if err != nil {
		t.Fatal(err)
	}
	back, err := evidence.UnmarshalReviewAttWire(mustMarshal(t, att))
	if err != nil {
		t.Fatal(err)
	}
	got, err := back.Verify(hub.KEL(), (day+2)*evidence.DayMS)
	if err != nil || got.Hub != hub.AID() || got.Type != evidence.ReviewAttType {
		t.Fatalf("a genuine attestation must verify: %+v, %v", got, err)
	}
	if _, err := back.Verify(other.KEL(), (day+2)*evidence.DayMS); !errors.Is(err, evidence.ErrSignature) {
		t.Fatalf("another hub's KEL: want ErrSignature, got %v", err)
	}
	named := *body
	named.Hub = hub.AID()
	if _, err := named.Sign(other); !errors.Is(err, evidence.ErrSigner) {
		t.Fatalf("signing another hub's attestation: want ErrSigner, got %v", err)
	}
	short := *body
	short.Tag = tag[:15]
	if _, err := short.Sign(hub); !errors.Is(err, evidence.ErrMalformed) {
		t.Fatalf("a 15-byte tag: want ErrMalformed, got %v", err)
	}
	// Moved to another signer, whose own KEL verifies the signature.
	raw2, err := named.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := body.Marshal(); !errors.Is(err, evidence.ErrMalformed) {
		t.Fatalf("an attestation that names no hub: want ErrMalformed, got %v", err)
	}
	sig, seq := other.Sign(raw2)
	moved := &evidence.ReviewAttWire{Body: raw2, Env: &aobj.Envelope{SignerAID: other.AID(), KeyStateSeq: seq, Alg: aobj.AlgEdDSA, Sig: sig}}
	if _, err := moved.Verify(other.KEL(), (day+2)*evidence.DayMS); !errors.Is(err, evidence.ErrSigner) {
		t.Fatalf("signer is not the hub: want ErrSigner, got %v", err)
	}
}
