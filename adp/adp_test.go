package adp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
)

func sha256Of(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// at returns a fixed verifier clock just after issued_at so freshness passes (within TTL).
func at(issuedAt int64) time.Time { return time.Unix(issuedAt+60, 0) }

// newCard returns a minimal well-formed card for subject==signer with a current issued_at.
func newCard(subjectDID string) *AgentCard {
	now := time.Now().Unix()
	return &AgentCard{
		SubjectDID:         subjectDID,
		CardSchema:         CardSchema{Major: SchemaMajor, Minor: SchemaMinor},
		Seq:                1,
		IssuedAt:           now,
		NotBefore:          now,
		Capabilities:       []string{"nlp/translation"},
		CriticalExtensions: []string{},
		ID:                 "agent://" + subjectDID,
		Name:               "test-card",
	}
}

// signedCard returns a fresh controller and a card self-signed by it (subject==signer).
func signedCard(t *testing.T) (*identity.Controller, *AgentCard) {
	t.Helper()
	c, err := identity.Incept()
	if err != nil {
		t.Fatalf("incept: %v", err)
	}
	card := newCard(c.AID())
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return c, card
}

func mustCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", want.Label)
	}
	if !IsCode(err, want) {
		t.Fatalf("expected %s, got %v", want.Label, err)
	}
}

// ---------------------------------------------------------------------------
// §6 ADP-GV-1 — frozen card_cid, JCS preimage, detached JWS (real values)
// ---------------------------------------------------------------------------

func TestADP_GV1_FrozenCardCIDAndPreimage(t *testing.T) {
	// Exact ADP-GV-1 fixture (adp-spec §6.1).
	card := &AgentCard{
		SubjectDID:         "did:anet:gv1",
		CardSchema:         CardSchema{Major: 1, Minor: 0},
		Seq:                1,
		IssuedAt:           1750000000,
		NotBefore:          1750000000,
		Capabilities:       []string{"nlp/translation"},
		Domains:            []string{"bridge"},
		CriticalExtensions: []string{},
		ID:                 "agent://did-anet-gv1",
		Name:               "gv1-card",
	}

	wantPreimageHex := "7b226361706162696c6974696573223a5b226e6c702f7472616e736c6174696f6e225d2c22636172645f736368656d61223a7b226d616a6f72223a317d2c22637269746963616c5f657874656e73696f6e73223a5b5d2c22646f6d61696e73223a5b22627269646765225d2c226964223a226167656e743a2f2f6469642d616e65742d677631222c226973737565645f6174223a313735303030303030302c226e616d65223a226776312d63617264222c226e6f745f6265666f7265223a313735303030303030302c22736571223a312c227375626a6563745f646964223a226469643a616e65743a677631227d"
	pre, err := card.Preimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	if got := hex.EncodeToString(pre); got != wantPreimageHex {
		t.Fatalf("JCS preimage mismatch\n got  %s\n want %s", got, wantPreimageHex)
	}

	const wantCID = "cog:1220d3e2b4982dacdc00719200f743a3ad7f303195796d076858d629f2c05913809c"
	cid, err := card.CardCID()
	if err != nil {
		t.Fatalf("card_cid: %v", err)
	}
	if cid != wantCID {
		t.Fatalf("card_cid mismatch\n got  %s\n want %s", cid, wantCID)
	}

	// Detached compact JWS under the suite test key (frozen in §6.1).
	if err := card.SignWithKey(suiteKey(), "did:anet:gv1", 0); err != nil {
		t.Fatalf("sign: %v", err)
	}
	const wantJWS = "eyJhbGciOiJFZERTQSJ9..UquIPxm6oWeeOCFsq5lETGoi7LjkH8wmfjlZB0dpgD_1J_NL1IEQsl6t4wYTTO2_gg-ifrnbIso_00DU6EVuAQ"
	if card.Envelope.Sig != wantJWS {
		t.Fatalf("detached JWS mismatch\n got  %s\n want %s", card.Envelope.Sig, wantJWS)
	}
}

// F1: RFC 8785 emits U+2028/U+2029 as RAW UTF-8, not the " "/" " escape Go's
// encoding/json writes even with SetEscapeHTML(false). A card whose `name` carries U+2028
// MUST produce a JCS pre-image with the raw 3-byte 0xE2 0x80 0xA8 sequence (no backslash-u),
// and its card_cid MUST differ from the (wrong) escaped-form CID. ADP-GV-1 (pure ASCII) is
// unaffected (asserted by TestADP_GV1_*).
func TestJCS_LineSeparator_RawUTF8_RFC8785(t *testing.T) {
	card := newCard("did:anet:u2028")
	card.Name = "a b" // U+2028 LINE SEPARATOR between 'a' and 'b'
	card.IssuedAt = 1750000000
	card.NotBefore = 1750000000

	pre, err := card.Preimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	// MUST contain the raw 3-byte UTF-8 for U+2028.
	if !bytes.Contains(pre, []byte{0xE2, 0x80, 0xA8}) {
		t.Fatalf("JCS pre-image missing raw U+2028 bytes:\n%s", hex.EncodeToString(pre))
	}
	// MUST NOT contain the 6-ASCII-char escape   (backslash-u-2028).
	if bytes.Contains(pre, []byte{0x5C, 'u', '2', '0', '2', '8'}) {
		t.Fatalf("JCS pre-image still carries the \\u2028 escape (RFC 8785 violation):\n%s", hex.EncodeToString(pre))
	}
	// card_cid over the raw-byte pre-image differs from the escaped-form CID.
	rawCID, err := card.CardCID()
	if err != nil {
		t.Fatalf("card_cid: %v", err)
	}
	escaped := bytes.ReplaceAll(pre, []byte{0xE2, 0x80, 0xA8}, []byte{0x5C, 'u', '2', '0', '2', '8'})
	escapedCID := "cog:" + hex.EncodeToString(multihashSHA256(escaped))
	if rawCID == escapedCID {
		t.Fatalf("card_cid did not change between raw-UTF8 and escaped forms: %s", rawCID)
	}
}

// suiteKey reproduces the _CONVENTIONS §8 suite test key (seed = SHA-256("anet-suite-test-key-v1")).
func suiteKey() ed25519.PrivateKey {
	// Mirror of aobj.SuiteSeed without importing aobj into adp.
	seed := sha256Of("anet-suite-test-key-v1")
	return ed25519.NewKeyFromSeed(seed)
}

// ---------------------------------------------------------------------------
// Happy path: a well-formed self-signed card admits
// ---------------------------------------------------------------------------

func TestAdmit_WellFormedSelfSigned(t *testing.T) {
	c, card := signedCard(t)
	disp, err := AdmitCard(card, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	if err != nil {
		t.Fatalf("expected admit, got %v", err)
	}
	if disp != DispPublished {
		t.Fatalf("expected PUBLISHED, got %s", disp)
	}
}

// ---------------------------------------------------------------------------
// Rejection drive — each §5.1 step
// ---------------------------------------------------------------------------

func TestReject_TamperedPreimage_INVALID_SIGNATURE(t *testing.T) {
	c, card := signedCard(t)
	// Mutate a CID-significant field AFTER signing: the recomputed preimage no longer matches.
	card.Capabilities = []string{"nlp/translation", "vision/ocr"}
	_, err := AdmitCard(card, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, INVALID_SIGNATURE)
}

func TestReject_StaleSeq(t *testing.T) {
	c, card := signedCard(t)
	// high_water already >= card.seq → rollback reject.
	_, err := AdmitCard(card, at(card.IssuedAt), card.Seq, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, STALE_SEQ)

	// Also seq strictly below high_water.
	_, err = AdmitCard(card, at(card.IssuedAt), card.Seq+5, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, STALE_SEQ)
}

func TestReject_SignerNotSubject_NoDelegation_UNAUTHORIZED_SIGNER(t *testing.T) {
	c, _ := signedCard(t)
	// A card whose subject_did is someone else, signed by c, with NO delegation_proof.
	card := newCard("did:anet:someone-else")
	if err := card.Sign(c); err != nil { // Sign does NOT overwrite a set subject_did
		t.Fatalf("sign: %v", err)
	}
	if card.SubjectDID != "did:anet:someone-else" {
		t.Fatalf("subject_did was overwritten")
	}
	_, err := AdmitCard(card, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, UNAUTHORIZED_SIGNER)
}

func TestAdmit_DelegatedPublish_WithProof(t *testing.T) {
	c, _ := signedCard(t)
	card := newCard("did:anet:someone-else")
	card.DelegationProof = []byte(`{"chain":"stub"}`) // present, non-empty → baseline accepts
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	disp, err := AdmitCard(card, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	if err != nil {
		t.Fatalf("delegated publish should admit at baseline, got %v", err)
	}
	if disp != DispPublished {
		t.Fatalf("expected PUBLISHED, got %s", disp)
	}
}

func TestReject_UnknownCriticalExtension_CRITICAL_EXTENSION_UNVERIFIABLE(t *testing.T) {
	c, _ := signedCard(t)
	card := newCard(c.AID())
	card.CriticalExtensions = []string{"adp.some-unknown-critical-label"}
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, err := AdmitCard(card, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, CRITICAL_EXTENSION_UNVERIFIABLE)
}

func TestReject_NotBeforeFarFuture_CARD_NOT_YET_VALID(t *testing.T) {
	c := mustIncept(t)
	card := newCard(c.AID())
	now := time.Now()
	// not_before well beyond now + ADP_FUTURE_SKEW (300 s).
	card.IssuedAt = now.Unix()
	card.NotBefore = now.Add(ADPFutureSkew + time.Hour).Unix()
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, err := AdmitCard(card, now, 0, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, CARD_NOT_YET_VALID)
}

func TestReject_UnsupportedSchemaMajor_UNSUPPORTED_SCHEMA_MAJOR(t *testing.T) {
	c := mustIncept(t)
	card := newCard(c.AID())
	card.CardSchema.Major = 2
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Node supports only MAJOR=1.
	_, err := AdmitCard(card, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, UNSUPPORTED_SCHEMA_MAJOR)
}

func TestReject_KeyStateSeqMismatch_KEY_STATE_DOWNGRADE(t *testing.T) {
	c := mustIncept(t)
	// Rotate so the current key_state_seq is 1, then sign a card under the current key.
	if err := c.Rotate(0); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	card := newCard(c.AID())
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if card.Envelope.KeyStateSeq != 1 {
		t.Fatalf("expected current key_state_seq 1, got %d", card.Envelope.KeyStateSeq)
	}

	// (a) Forge a downgrade to the OLD seq 0: the seq-1 signature does NOT verify under the
	// seq-0 key VerifyObject selects → INVALID_SIGNATURE (spec verdict under the as-of-time
	// gate; the manual `seq==tip` short-circuit that masked this as KEY_STATE_DOWNGRADE was
	// the F2 defect — both readings still REJECT, so no trust is granted).
	forgedOld := *card
	forgedOld.Envelope.KeyStateSeq = 0
	_, err := AdmitCard(&forgedOld, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, INVALID_SIGNATURE)

	// (b) Claim a key_state_seq BEYOND the KEL tip → KEY_STATE_DOWNGRADE (anti-downgrade,
	// M5.1.2): there is no such key-state to select.
	forgedHi := *card
	forgedHi.Envelope.KeyStateSeq = 99
	_, err = AdmitCard(&forgedHi, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, KEY_STATE_DOWNGRADE)
}

// F3 grace: a card SIGNED at seq 0 whose issued_at predates a LATER rotation MUST verify
// (as-of-time grace, §5.1 step3 ks=KeyState(signer_aid, issued_at) + step4 grace M5.1.3).
// The strict `key_state_seq == KEL tip` reading rejected this legitimately pre-rotation
// card; the VerifyObject-based gate admits it.
func TestAdmit_PreRotationCard_GraceAdmits(t *testing.T) {
	c := mustIncept(t)
	// Sign a card under the inception key (seq 0), issued at T0.
	t0 := time.Unix(1750000000, 0)
	card := newCard(c.AID())
	card.IssuedAt = t0.Unix()
	card.NotBefore = t0.Unix()
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if card.Envelope.KeyStateSeq != 0 {
		t.Fatalf("expected seq 0 signature, got %d", card.Envelope.KeyStateSeq)
	}
	// Rotate the controller LATER (rotation timestamp T0 + 1h, in unix-millis).
	rotMillis := uint64(t0.Add(time.Hour).UnixMilli())
	if err := c.Rotate(rotMillis); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// The card was issued BEFORE the rotation → grace → ADMIT against the rotated KEL.
	disp, err := AdmitCard(card, t0.Add(time.Minute), 0, c.KEL(), SupportedMajors(1), nil)
	if err != nil {
		t.Fatalf("pre-rotation card must admit (grace), got %v", err)
	}
	if disp != DispPublished {
		t.Fatalf("expected PUBLISHED, got %s", disp)
	}
}

// F3 revocation: a card SIGNED at seq 0 but issued_at AT/AFTER the later rotation is
// REVOKED_KEY (the seq-0 key was already retired when the card was bound, §5.1 step4 M5.1.3).
func TestReject_PostRotationSeq0Card_REVOKED_KEY(t *testing.T) {
	c := mustIncept(t)
	t0 := time.Unix(1750000000, 0)
	rotMillis := uint64(t0.Add(time.Hour).UnixMilli())
	// Sign the card under seq 0 but stamp issued_at AFTER the rotation time.
	afterRot := t0.Add(2 * time.Hour)
	card := newCard(c.AID())
	card.IssuedAt = afterRot.Unix()
	card.NotBefore = afterRot.Unix()
	if err := card.Sign(c); err != nil { // signed under seq 0 (controller not yet rotated)
		t.Fatalf("sign: %v", err)
	}
	if card.Envelope.KeyStateSeq != 0 {
		t.Fatalf("expected seq 0 signature, got %d", card.Envelope.KeyStateSeq)
	}
	if err := c.Rotate(rotMillis); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	_, err := AdmitCard(card, afterRot.Add(time.Minute), 0, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, REVOKED_KEY)
}

func TestReject_UnknownAID(t *testing.T) {
	c, card := signedCard(t)
	other := mustIncept(t) // a different KEL whose AID != card signer
	_, err := AdmitCard(card, at(card.IssuedAt), 0, other.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, UNKNOWN_AID)
	_ = c
}

// ---------------------------------------------------------------------------
// admit-then-EXPIRE (§5.1 step 7 already-expired branch / T5)
// ---------------------------------------------------------------------------

func TestAdmitThenExpire(t *testing.T) {
	c := mustIncept(t)
	card := newCard(c.AID())
	// not_before far in the past so now > not_before + ADP_CARD_TTL.
	past := time.Now().Add(-2 * ADPCardTTL)
	card.IssuedAt = past.Unix()
	card.NotBefore = past.Unix()
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	disp, err := AdmitCard(card, time.Now(), 0, c.KEL(), SupportedMajors(1), nil)
	if err != nil {
		t.Fatalf("already-expired card must be admitted (not rejected), got %v", err)
	}
	if disp != DispExpired {
		t.Fatalf("expected EXPIRED disposition, got %s", disp)
	}
}

// ---------------------------------------------------------------------------
// domains[] — typed field, round-trips, still admits
// ---------------------------------------------------------------------------

func TestDomains_RoundTripAndAdmit(t *testing.T) {
	c := mustIncept(t)
	card := newCard(c.AID())
	card.Domains = []string{"bridge", "drainage"}
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	disp, err := AdmitCard(card, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	if err != nil {
		t.Fatalf("card with domains must admit, got %v", err)
	}
	if disp != DispPublished {
		t.Fatalf("expected PUBLISHED, got %s", disp)
	}
	// domains[] is a typed schema field, not an extension label — it never raised
	// CRITICAL_EXTENSION_UNVERIFIABLE even though no extension labels are understood.
	if len(card.CriticalExtensions) != 0 {
		t.Fatalf("domains[] leaked into critical_extensions")
	}
}

// ---------------------------------------------------------------------------
// CardCID determinism + MINOR-invariance (§5.2.1)
// ---------------------------------------------------------------------------

func TestCardCID_Deterministic_And_MinorInvariant(t *testing.T) {
	mk := func(minor uint16) *AgentCard {
		card := newCard("did:anet:det")
		card.CardSchema = CardSchema{Major: 1, Minor: minor}
		card.IssuedAt = 1750000000
		card.NotBefore = 1750000000
		card.Domains = []string{"bridge"}
		return card
	}
	a := mk(0)
	b := mk(0)
	cidA, _ := a.CardCID()
	cidB, _ := b.CardCID()
	if cidA != cidB {
		t.Fatalf("card_cid not deterministic: %s vs %s", cidA, cidB)
	}
	// MINOR bump MUST NOT change card_cid (§5.2.1 MAJOR-only significance).
	bumped := mk(7)
	cidBumped, _ := bumped.CardCID()
	if cidBumped != cidA {
		t.Fatalf("MINOR bump changed card_cid: %s != %s", cidBumped, cidA)
	}
}

// ---------------------------------------------------------------------------
// CardTombstone — self-signed admits; third-party / low-seq rejected (§5.4, ADP-GV-3)
// ---------------------------------------------------------------------------

func TestTombstone_SelfSignedAdmits(t *testing.T) {
	c, _ := signedCard(t)
	tb := &CardTombstone{
		SubjectDID:     c.AID(),
		Seq:            10,
		RevokedCardCID: "cog:deadbeef",
		IssuedAt:       time.Now().Unix(),
	}
	if err := tb.Sign(c); err != nil {
		t.Fatalf("sign tombstone: %v", err)
	}
	if err := AdmitTombstone(tb, 9, c.KEL()); err != nil {
		t.Fatalf("self-signed tombstone seq>high_water must admit, got %v", err)
	}
}

func TestTombstone_ThirdParty_UNAUTHORIZED_REVOKE(t *testing.T) {
	victim := mustIncept(t)
	attacker := mustIncept(t)
	tb := &CardTombstone{
		SubjectDID:     victim.AID(), // revoking the victim
		Seq:            10,
		RevokedCardCID: "cog:deadbeef",
		IssuedAt:       time.Now().Unix(),
	}
	// Attacker signs — signer_aid becomes attacker.AID() != subject_did.
	if err := tb.Sign(attacker); err != nil {
		t.Fatalf("sign: %v", err)
	}
	err := AdmitTombstone(tb, 9, attacker.KEL())
	mustCode(t, err, UNAUTHORIZED_REVOKE)
}

func TestTombstone_LowSeq_STALE_SEQ(t *testing.T) {
	c := mustIncept(t)
	tb := &CardTombstone{
		SubjectDID:     c.AID(),
		Seq:            5,
		RevokedCardCID: "cog:deadbeef",
		IssuedAt:       time.Now().Unix(),
	}
	if err := tb.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	err := AdmitTombstone(tb, 5, c.KEL()) // seq == high_water → STALE_SEQ
	mustCode(t, err, STALE_SEQ)
}

// ---------------------------------------------------------------------------
// CardStore — verify-before-cache, NO-TOFU, idempotency, no mutation on reject
// ---------------------------------------------------------------------------

func TestStore_PutAdmitsAndCaches(t *testing.T) {
	c, card := signedCard(t)
	s := NewCardStore(SupportedMajors(1), nil)
	disp, err := s.Put(card, at(card.IssuedAt), c.KEL())
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if disp != DispPublished {
		t.Fatalf("expected PUBLISHED, got %s", disp)
	}
	if s.HighWater(card.SubjectDID) != card.Seq {
		t.Fatalf("high_water not advanced")
	}
	if s.Get(card.SubjectDID) == nil {
		t.Fatalf("card not cached after admit")
	}
}

// No trust-on-first-publish: an unsigned/forged card never bypasses AdmitCard on first sight,
// and a rejected card leaves NO store entry.
func TestStore_NoTOFU_NoMutationOnReject(t *testing.T) {
	c, card := signedCard(t)
	// Forge: tamper a CID-significant field after signing.
	card.Seq = 2 // not in preimage? seq IS in preimage → breaks the signature
	s := NewCardStore(SupportedMajors(1), nil)
	_, err := s.Put(card, at(card.IssuedAt), c.KEL())
	mustCode(t, err, INVALID_SIGNATURE)
	if s.Get(card.SubjectDID) != nil {
		t.Fatalf("rejected card was cached (NO-TOFU / verify-before-side-effect violated)")
	}
	if s.HighWater(card.SubjectDID) != 0 {
		t.Fatalf("rejected card advanced high_water")
	}
	if s.State(card.SubjectDID) != "" {
		t.Fatalf("rejected card created FSM state")
	}
}

func TestStore_Idempotent_SameCardCID(t *testing.T) {
	c, card := signedCard(t)
	s := NewCardStore(SupportedMajors(1), nil)
	if _, err := s.Put(card, at(card.IssuedAt), c.KEL()); err != nil {
		t.Fatalf("first put: %v", err)
	}
	// Same card again — same card_cid, same key_state → verified no-op (NOT STALE_SEQ).
	disp, err := s.Put(card, at(card.IssuedAt), c.KEL())
	if err != nil {
		t.Fatalf("idempotent re-put should be a no-op, got %v", err)
	}
	if disp != DispPublished {
		t.Fatalf("expected PUBLISHED no-op, got %s", disp)
	}
}

func TestStore_HighWaterSurvivesRestart_RollbackReject(t *testing.T) {
	c, card := signedCard(t)
	card.Seq = 9
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	s := NewCardStore(SupportedMajors(1), nil)
	// Model restart: high_water=9 restored from the §5.3 persistent row before any Put.
	s.SetHighWater(card.SubjectDID, 9)
	_, err := s.Put(card, at(card.IssuedAt), c.KEL()) // seq==9 <= high_water
	mustCode(t, err, STALE_SEQ)
}

// F7 §4.6 counters: card_verify_fail bumps on any verify failure; rollback_reject bumps on
// a STALE_SEQ rollback (ADP-GV-5). A clean admit bumps neither.
func TestStore_Counters_VerifyFailAndRollbackReject(t *testing.T) {
	c, card := signedCard(t)
	card.Seq = 9
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	s := NewCardStore(SupportedMajors(1), nil)
	// Clean admit: no counter movement.
	if _, err := s.Put(card, at(card.IssuedAt), c.KEL()); err != nil {
		t.Fatalf("put: %v", err)
	}
	if s.CardVerifyFail() != 0 || s.RollbackReject() != 0 {
		t.Fatalf("clean admit moved counters: verifyFail=%d rollback=%d", s.CardVerifyFail(), s.RollbackReject())
	}
	// STALE_SEQ rollback: a re-publish at seq 9 (== high_water) bumps BOTH counters. Give it a
	// distinct name so its card_cid differs from the cached one (else idempotency no-ops it).
	replay := newCard(c.AID())
	replay.Seq = 9
	replay.Name = "rollback-attempt"
	if err := replay.Sign(c); err != nil {
		t.Fatalf("sign replay: %v", err)
	}
	_, err := s.Put(replay, at(replay.IssuedAt), c.KEL())
	mustCode(t, err, STALE_SEQ)
	if s.CardVerifyFail() != 1 {
		t.Fatalf("card_verify_fail = %d, want 1", s.CardVerifyFail())
	}
	if s.RollbackReject() != 1 {
		t.Fatalf("rollback_reject = %d, want 1", s.RollbackReject())
	}
	// A non-rollback verify failure (forged signature) bumps card_verify_fail only.
	forged := newCard(c.AID())
	forged.Seq = 20
	if err := forged.Sign(c); err != nil {
		t.Fatalf("sign forged: %v", err)
	}
	forged.Capabilities = []string{"tampered"} // break the signature post-sign
	_, err = s.Put(forged, at(forged.IssuedAt), c.KEL())
	mustCode(t, err, INVALID_SIGNATURE)
	if s.CardVerifyFail() != 2 {
		t.Fatalf("card_verify_fail = %d, want 2", s.CardVerifyFail())
	}
	if s.RollbackReject() != 1 {
		t.Fatalf("rollback_reject moved on non-rollback failure: %d, want 1", s.RollbackReject())
	}
}

func TestStore_RevokeThenNoReuse(t *testing.T) {
	c, card := signedCard(t)
	s := NewCardStore(SupportedMajors(1), nil)
	if _, err := s.Put(card, at(card.IssuedAt), c.KEL()); err != nil {
		t.Fatalf("put: %v", err)
	}
	tb := &CardTombstone{
		SubjectDID:     c.AID(),
		Seq:            card.Seq + 1,
		RevokedCardCID: mustCID(t, card),
		IssuedAt:       time.Now().Unix(),
	}
	if err := tb.Sign(c); err != nil {
		t.Fatalf("sign tombstone: %v", err)
	}
	if err := s.Revoke(tb, c.KEL()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if s.Get(c.AID()) != nil {
		t.Fatalf("card still present after revoke")
	}
	if s.HighWater(c.AID()) != tb.Seq {
		t.Fatalf("revoke did not advance high_water to tombstone.seq")
	}
	// A later re-publish reusing the tombstone seq is STALE_SEQ.
	replay := newCard(c.AID())
	replay.Seq = tb.Seq
	if err := replay.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, err := s.Put(replay, at(replay.IssuedAt), c.KEL())
	mustCode(t, err, STALE_SEQ)
}

// ---------------------------------------------------------------------------
// Genome resolver (§5.1 step 8a/8b)
// ---------------------------------------------------------------------------

type fakeGenome struct{ ok, conformant bool }

func (f fakeGenome) FetchSpecies(string) (bool, bool)  { return f.ok, f.conformant }
func (f fakeGenome) FetchInstance(string) (bool, bool) { return f.ok, f.conformant }

func TestGenome_DanglingAndConformance(t *testing.T) {
	c := mustIncept(t)
	mk := func() *AgentCard {
		card := newCard(c.AID())
		card.Genome = &Genome{SpeciesCID: "bafyrei-stub-species"}
		if err := card.Sign(c); err != nil {
			t.Fatalf("sign: %v", err)
		}
		return card
	}

	// No resolver → DANGLING_GENOME_CID.
	_, err := AdmitCard(mk(), at(time.Now().Unix()), 0, c.KEL(), SupportedMajors(1), nil)
	mustCode(t, err, DANGLING_GENOME_CID)

	// Resolver says not found → DANGLING_GENOME_CID.
	_, err = AdmitCard(mk(), at(time.Now().Unix()), 0, c.KEL(), SupportedMajors(1), fakeGenome{ok: false})
	mustCode(t, err, DANGLING_GENOME_CID)

	// Found but not conformant → GENOME_CONFORMANCE_FAIL.
	_, err = AdmitCard(mk(), at(time.Now().Unix()), 0, c.KEL(), SupportedMajors(1), fakeGenome{ok: true, conformant: false})
	mustCode(t, err, GENOME_CONFORMANCE_FAIL)

	// Found and conformant → admits.
	disp, err := AdmitCard(mk(), at(time.Now().Unix()), 0, c.KEL(), SupportedMajors(1), fakeGenome{ok: true, conformant: true})
	if err != nil {
		t.Fatalf("conformant genome card must admit, got %v", err)
	}
	if disp != DispPublished {
		t.Fatalf("expected PUBLISHED, got %s", disp)
	}
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

func TestConstants_GossipTopic(t *testing.T) {
	if got := GossipTopic(1); got != "/anet/adp/v1" {
		t.Fatalf("gossip topic for MAJOR=1: got %s want /anet/adp/v1", got)
	}
	if RetiredTopic != "/anet/resumes" {
		t.Fatalf("retired topic constant wrong: %s", RetiredTopic)
	}
	if GossipTopic(1) == RetiredTopic {
		t.Fatalf("gossip topic must not be the retired /anet/resumes")
	}
	if ProtoNumber != 3 {
		t.Fatalf("proto number must be 3 (FROZEN), got %d", ProtoNumber)
	}
}

// ---------------------------------------------------------------------------
// F5 ADP-GV-4 — SchemaVersionTag gate fires BEFORE JSON parse (§2.4)
// ---------------------------------------------------------------------------

func TestGV4_GossipSchemaTag_UnsupportedMajorBeforeParse(t *testing.T) {
	// Payload 0x02 ‖ (deliberately INVALID JSON). A {1}-only node MUST reject on the tag
	// byte alone — UNSUPPORTED_SCHEMA_MAJOR — without ever parsing the (broken) JSON.
	payload := append([]byte{0x02}, []byte(`this is not json at all`)...)
	card, err := ParseGossip(payload, SupportedMajors(1))
	if card != nil {
		t.Fatalf("unsupported-MAJOR payload must not yield a card")
	}
	mustCode(t, err, UNSUPPORTED_SCHEMA_MAJOR)

	// A supported tag 0x01 ‖ well-formed publish envelope parses and admits.
	c, signed := signedCard(t)
	env := GossipCardMessage{Action: "publish", Card: signed, AgentID: c.AID(), Seq: signed.Seq, Timestamp: "2026-06-14T00:00:00Z"}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal env: %v", err)
	}
	tagged := append([]byte{0x01}, body...)
	got, err := ParseGossip(tagged, SupportedMajors(1))
	if err != nil {
		t.Fatalf("tagged 0x01 publish must parse, got %v", err)
	}
	if got == nil {
		t.Fatalf("expected a card from a publish envelope")
	}
	disp, err := AdmitCard(got, at(got.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	if err != nil || disp != DispPublished {
		t.Fatalf("parsed card must admit: disp=%s err=%v", disp, err)
	}
}

// ---------------------------------------------------------------------------
// F5 ADP-GV-10 — untagged-legacy bare card: parses, AdmitCard → MALFORMED_CARD,
// no cache mutation (§2.4 first-byte caveat, §6 ADP-GV-10)
// ---------------------------------------------------------------------------

func TestGV10_LegacyBareCard_ParsesThenMalformed_NoCacheMutation(t *testing.T) {
	// A captured legacy card: skills/signature, NO card_schema/envelope. The payload begins
	// with '{' (0x7B) — the untagged-legacy regime (not MAJOR 123).
	legacy := []byte(`{"subject_did":"did:anet:legacy","skills":["nlp/translation"],"signature":"eyJhbGciOiJFZERTQSJ9..AAAA","name":"old-card","seq":1}`)
	if legacy[0] != 0x7B {
		t.Fatalf("legacy payload must begin with '{' (0x7B)")
	}
	card, err := ParseGossip(legacy, SupportedMajors(1))
	if err != nil {
		t.Fatalf("legacy bare card must PARSE (wire-preserved), got %v", err)
	}
	if card == nil || card.SubjectDID != "did:anet:legacy" || len(card.Skills) != 1 {
		t.Fatalf("legacy keys not wire-preserved: %+v", card)
	}
	// AdmitCard rejects: no envelope → MALFORMED_CARD; verify-before-cache leaves NO entry.
	s := NewCardStore(SupportedMajors(1), nil)
	_, err = s.Put(card, time.Now(), nil)
	mustCode(t, err, MALFORMED_CARD)
	if s.Get(card.SubjectDID) != nil {
		t.Fatalf("rejected legacy card was cached (verify-before-cache violated)")
	}
	if s.HighWater(card.SubjectDID) != 0 || s.State(card.SubjectDID) != "" {
		t.Fatalf("rejected legacy card mutated store state")
	}
}

// ---------------------------------------------------------------------------
// F6 ADP-GV-9 — cross-MINOR: a {1,1} card admits at a {1,0} node; the MINOR bump
// leaves card_cid unchanged; domains[] ignored-and-preserved (§5.2.1, §6 ADP-GV-9)
// ---------------------------------------------------------------------------

func TestGV9_CrossMinor_AdditiveAccept(t *testing.T) {
	c := mustIncept(t)
	card := newCard(c.AID())
	card.CardSchema = CardSchema{Major: 1, Minor: 1} // higher MINOR than this {1,0} node
	card.Domains = []string{"bridge", "drainage"}    // additive field the {1,0} node MUST preserve
	if err := card.Sign(c); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// A {1,0}-built node (supports MAJOR 1) MUST accept the {1,1} card (MINOR-additive).
	disp, err := AdmitCard(card, at(card.IssuedAt), 0, c.KEL(), SupportedMajors(1), nil)
	if err != nil {
		t.Fatalf("cross-MINOR {1,1} card must admit at a {1,0} node, got %v", err)
	}
	if disp != DispPublished {
		t.Fatalf("expected PUBLISHED, got %s", disp)
	}
	// MINOR-invariant card_cid (§5.2.1): the same card at MINOR 0 has an identical card_cid.
	cidBumped := mustCID(t, card)
	card0 := *card
	card0.CardSchema.Minor = 0
	if got := mustCID(t, &card0); got != cidBumped {
		t.Fatalf("MINOR bump changed card_cid: %s != %s", got, cidBumped)
	}
	// domains[] preserved byte-intact (ignored-and-preserved on a pre-domains node).
	if len(card.Domains) != 2 || card.Domains[0] != "bridge" || card.Domains[1] != "drainage" {
		t.Fatalf("domains[] not preserved: %+v", card.Domains)
	}
}

// ---------------------------------------------------------------------------
// small local helpers
// ---------------------------------------------------------------------------

func mustIncept(t *testing.T) *identity.Controller {
	t.Helper()
	c, err := identity.Incept()
	if err != nil {
		t.Fatalf("incept: %v", err)
	}
	return c
}

func mustCID(t *testing.T, card *AgentCard) string {
	t.Helper()
	cid, err := card.CardCID()
	if err != nil {
		t.Fatalf("card_cid: %v", err)
	}
	return cid
}
