// Package adp implements the P3 Agent Description Protocol (ADP) card plane:
// the AgentCard JSON schema, its JCS detached-JWS pre-image and card_cid, the
// verify-before-cache AdmitCard gate, the self-signed CardTombstone revoke, and
// the persistent per-DID high-water CardStore.
//
// Normative source: design3/spec/adp-spec.md (paired with draft-song-agentnetwork-adp-03).
// Encoding posture (§2.1): the card path is JSON under profile adp-card (JCS detached-JWS,
// §3.1) — NOT CBOR. The genome CAS path (§2.5, CoreDet-CBOR) is carriage-typed here via the
// genome.{species,instance}_cid fields and a stubbed resolver; its value semantics are
// Experimental (ascp-evo-03).
//
// Invariants this package fixes:
//   - The card_cid is the suite-local cog:-prefixed multihash over the adp-card JCS pre-image
//     (§3.4); a MINOR bump MUST NOT change it (§5.2.1 MAJOR-only significance).
//   - Verify-before-cache is a HARD precondition on EVERY Put and EVERY gossip ingest (§5.1);
//     there is NO trust-on-first-publish path.
//   - On any AdmitCard failure: typed SCREAMING_CASE error (§4.5), NO cache mutation, NO
//     silent drop (verify-before-side-effect, P1 P1.5).
//   - The per-DID high_water seq survives restart (§5.3) and is CAS-guarded (strictly higher).
//   - A revoke is ONLY a subject-self-signed CardTombstone (§2.3, §5.4); a third-party or
//     low-seq tombstone is rejected.
package adp

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"time"

	"github.com/ANetResearch/ANetCore/identity"
)

// ---- §4 constants (adp-spec §4.2 / §4.4) ----

const (
	// ProtoNumber is the ALP proto-mux number for ADP — FROZEN MUST (§4.1).
	ProtoNumber = 3

	// SchemaMajor / SchemaMinor are the card_schema this build emits (§6: card_schema={1,0}).
	SchemaMajor uint16 = 1
	SchemaMinor uint16 = 0

	// AlgEdDSA is the FROZEN envelope alg string for the adp-card JSON projection (§2.6, §4.4).
	// (The CBOR genome path uses the COSE int -8; the card path uses this JOSE string.)
	AlgEdDSA = "EdDSA"

	// MaxNameLen / MaxDescriptionLen / MaxSkills / MaxCardSize are the §2.7 size limits.
	MaxNameLen        = 128
	MaxDescriptionLen = 4096
	MaxSkills         = 50
	MaxCardSize       = 65535

	// RetiredTopic is the pre-versioned gossip topic; a conformant node MUST NOT subscribe
	// to or publish on it (§4.2 / §4.4). The normative topic is GossipTopic(major).
	RetiredTopic = "/anet/resumes"

	// ADP_FUTURE_SKEW: anti-pre-dating tolerance, §5.1 step 7 (default 300 s; range 0..3600 s).
	ADPFutureSkew = 300 * time.Second
	// ADP_CARD_TTL: card freshness lifetime, §5.2 T5 (default 7 d; range 1 h..90 d).
	ADPCardTTL = 7 * 24 * time.Hour
	// ADP_GENOME_FETCH_TIMEOUT: genome self-consistency fetch budget, §5.1 step 8a (default 10 s).
	ADPGenomeFetchTimeout = 10 * time.Second
)

// GossipTopic returns the normative versioned gossip topic for a card MAJOR (§4.2):
// "/anet/adp/v<MAJOR>" (MAJOR=1 ⇒ "/anet/adp/v1"). One topic per supported MAJOR.
func GossipTopic(major uint16) string {
	return "/anet/adp/v" + strconv.FormatUint(uint64(major), 10)
}

// ---- §2.2 AgentCard ----

// CardSchema is the card_schema MUST field (§2.2). Only Major is CID-significant (§5.2.1):
// it enters the adp-card pre-image as {"major":N}; Minor is excluded (§3.1).
type CardSchema struct {
	Major uint16 `json:"major"`
	Minor uint16 `json:"minor"`
}

// Genome carries the typed content-addresses of the species/instance genome (§2.2). These
// are the ONLY genome references on a card; an untyped content-address under extensions{} is
// a descriptive label, never a genome reference. Experimental semantics: ascp-evo-03 (§2.5).
type Genome struct {
	SpeciesCID  string `json:"species_cid,omitempty"`
	InstanceCID string `json:"instance_cid,omitempty"`
}

// Lineage is a NON-AUTHORITATIVE descriptive label (§2.2, §5.5): a code-identity hash grants
// nothing. Wire-preserved but never a source of authority.
type Lineage struct {
	Class    string `json:"class,omitempty"`
	CodeHash string `json:"code_hash,omitempty"`
}

// EnvelopeJSON is the aobj-envelope-json card/tombstone-path envelope (§2.6): the legacy
// JSON projection of the AObjEnvelope (_CONVENTIONS §5) that signs with detached JWS over
// JCS-JSON instead of raw Ed25519. Sig is the compact detached JWS
// "BASE64URL(header)..BASE64URL(sig)" (alg=EdDSA) over the §3.1 adp-card pre-image.
type EnvelopeJSON struct {
	SignerAID   string `json:"signer_aid"`
	KeyStateSeq uint64 `json:"key_state_seq"`
	Alg         string `json:"alg"`
	Sig         string `json:"sig"` // detached compact JWS (header..sig), payload omitted
}

// ToolDesc / EndpointDesc / Constraints / Metadata are the wire-preserved descriptive
// sub-objects (§2.2); they parse and round-trip but are NOT CID-significant beyond being
// present in the JCS object.
type ToolDesc struct {
	Name         string          `json:"name"`
	Description  string          `json:"description,omitempty"`
	InputSchema  json.RawMessage `json:"input_schema,omitempty"`
	OutputSchema json.RawMessage `json:"output_schema,omitempty"`
	Streaming    *bool           `json:"streaming,omitempty"`
	Idempotent   *bool           `json:"idempotent,omitempty"`
	ExampleCall  json.RawMessage `json:"example_call,omitempty"`
}

// EndpointDesc is a non-authoritative ANRP-resolution hint (§2.2).
type EndpointDesc struct {
	Protocol string   `json:"protocol"`
	URI      string   `json:"uri"`
	Methods  []string `json:"methods,omitempty"`
	Auth     string   `json:"auth,omitempty"`
	Priority *int     `json:"priority,omitempty"`
}

// Constraints is a wire-preserved descriptive sub-object (§2.2).
type Constraints struct {
	MaxConcurrentTasks *uint64  `json:"max_concurrent_tasks,omitempty"`
	MaxInputTokens     *uint64  `json:"max_input_tokens,omitempty"`
	SupportedLanguages []string `json:"supported_languages,omitempty"`
	RateLimit          string   `json:"rate_limit,omitempty"`
	RequiresDeposit    *bool    `json:"requires_deposit,omitempty"`
	MinReputation      *int     `json:"min_reputation,omitempty"`
}

// Metadata is a wire-preserved descriptive sub-object (§2.2).
type Metadata struct {
	CreatedAt string  `json:"created_at,omitempty"`
	UpdatedAt string  `json:"updated_at,omitempty"`
	TTL       *uint64 `json:"ttl,omitempty"`
}

// AgentCard is the §2.2 AgentCard (profile adp-card, JSON/JCS). All CID-significant fields
// live inside the signable pre-image (§3.1); descriptive and legacy keys are wire-preserved
// (a captured legacy card still parses, §6 ADP-GV-10).
type AgentCard struct {
	// --- canonical identity & schema (MUST) ---
	SubjectDID         string     `json:"subject_did"`
	CardSchema         CardSchema `json:"card_schema"`
	Seq                uint64     `json:"seq"`
	IssuedAt           int64      `json:"issued_at"`  // unix-s; KeyState as-of time (§2.2)
	NotBefore          int64      `json:"not_before"` // unix-s; freshness floor (§5.1 step 7)
	Capabilities       []string   `json:"capabilities"`
	Domains            []string   `json:"domains,omitempty"` // OPTIONAL fourth paper facet (§2.2)
	CriticalExtensions []string   `json:"critical_extensions"`

	// --- optional structured (§2.2) ---
	Genome          *Genome         `json:"genome,omitempty"`
	Lineage         *Lineage        `json:"lineage,omitempty"`
	DelegationProof json.RawMessage `json:"delegation_proof,omitempty"` // MUST for delegated publish; in pre-image

	// --- authoritative signature (MUST) ---
	Envelope EnvelopeJSON `json:"envelope"`

	// --- descriptive & legacy keys (wire-preserved, §2.2) ---
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Version     string         `json:"version,omitempty"`
	Skills      []string       `json:"skills,omitempty"` // legacy alias of capabilities[]
	Tools       []ToolDesc     `json:"tools,omitempty"`
	Endpoints   []EndpointDesc `json:"endpoints,omitempty"`
	Constraints *Constraints   `json:"constraints,omitempty"`
	DID         string         `json:"did,omitempty"` // legacy alias of subject_did
	Metadata    *Metadata      `json:"metadata,omitempty"`
	Extensions  map[string]any `json:"extensions,omitempty"`
	Signature   string         `json:"signature,omitempty"` // legacy detached JWS — superseded by envelope; excluded from pre-image (§3.1)
}

// ---- §3.1 adp-card pre-image (JCS) + §3.4 card_cid ----

// preimageFields excluded from the adp-card JCS pre-image, per the §3.1 profile row
// {excluded_fields=[envelope, signature (legacy)]} plus the §5.2.1 MAJOR-only rule that
// excludes card_schema.minor. Everything ELSE present on the card (including descriptive
// keys id/name/... — see ADP-GV-1, whose pre-image carries id+name) is in the pre-image:
// the rule is "whole card object minus these exclusions", NOT a positive whitelist.
//
// Preimage builds the CID-significant view: marshal the card to a generic JSON object,
// drop the excluded keys, collapse card_schema to {"major":N}, then JCS-canonicalize.
func (c *AgentCard) preimageObject() (map[string]any, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, &Error{Code: MALFORMED_CARD, Detail: "card not marshalable: " + err.Error()}
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, &Error{Code: MALFORMED_CARD, Detail: "card not a JSON object: " + err.Error()}
	}
	// §3.1 exclusions.
	delete(obj, "envelope")  // the card's own signature is never in its own pre-image
	delete(obj, "signature") // legacy detached JWS — MUST be absent (§2.2/§3.1)
	// §5.2.1: only card_schema.major is CID-significant; minor MUST NOT fork card_cid.
	if cs, ok := obj["card_schema"].(map[string]any); ok {
		if maj, ok := cs["major"]; ok {
			obj["card_schema"] = map[string]any{"major": maj}
		}
	}
	return obj, nil
}

// Preimage returns the adp-card canonical pre-image: RFC 8785 JCS bytes of the
// CID-significant card view (§3.1). The bytes are what the detached JWS signs and what
// card_cid is taken over.
func (c *AgentCard) Preimage() ([]byte, error) {
	obj, err := c.preimageObject()
	if err != nil {
		return nil, err
	}
	return jcsMarshal(obj)
}

// multihashSHA256 returns the raw multihash 0x12 0x20 ‖ sha2-256(data) (_CONVENTIONS §3).
func multihashSHA256(data []byte) []byte {
	d := sha256.Sum256(data)
	out := make([]byte, 0, 2+len(d))
	out = append(out, 0x12, 0x20)
	out = append(out, d[:]...)
	return out
}

// CardCID returns the card_cid (§3.4): the suite-local cog:-prefixed lowercase-hex rendering
// of 0x12 0x20 ‖ sha2-256(adp-card JCS pre-image). This OVERRIDES _CONVENTIONS §3 for the card
// path: it is NOT the "b"‖base32 CIDv1/dag-cbor form and carries no 0x01 0x71 prefix (the cog:
// prefix is a suite-local convention, not a registered multibase code). A MINOR bump leaves it
// unchanged (§5.2.1) because card_schema.minor is excluded from the pre-image.
func (c *AgentCard) CardCID() (string, error) {
	pre, err := c.Preimage()
	if err != nil {
		return "", err
	}
	return "cog:" + hex.EncodeToString(multihashSHA256(pre)), nil
}

// ---- detached compact JWS (§2.6, §3.1) ----

var b64url = base64.RawURLEncoding

// jwsProtectedHeader is the FROZEN protected header for the adp-card detached JWS (§2.6).
// It is exactly {"alg":"EdDSA"} with no whitespace (the §6 ADP-GV-1 signing input depends on
// these exact bytes).
var jwsProtectedHeader = []byte(`{"alg":"EdDSA"}`)

// jwsSigningInput returns the compact-JWS signing input over preimage: the FROZEN protected
// header and the pre-image, each BASE64URL, joined by "." (RFC 7515; alg=EdDSA, §2.6). The
// header b64 and the full signing input are returned so the caller can assemble the wire form.
func jwsSigningInput(preimage []byte) (hdrB64 string, signingInput []byte) {
	hdrB64 = b64url.EncodeToString(jwsProtectedHeader)
	return hdrB64, []byte(hdrB64 + "." + b64url.EncodeToString(preimage))
}

// assembleDetachedJWS builds the compact detached-JWS wire form BASE64URL(header)".."BASE64URL(sig)
// with the payload omitted (RFC 7515 Appendix F detached content).
func assembleDetachedJWS(hdrB64 string, sig []byte) string {
	return hdrB64 + ".." + b64url.EncodeToString(sig)
}

// signDetachedJWS produces the compact detached JWS over preimage with a raw private key.
// Used by the suite-test signing path; the controller path goes through Controller.Sign.
func signDetachedJWS(priv ed25519.PrivateKey, preimage []byte) string {
	hdrB64, signingInput := jwsSigningInput(preimage)
	return assembleDetachedJWS(hdrB64, ed25519.Sign(priv, signingInput))
}

// decodeDetachedJWS parses a compact detached JWS (header..sig) over preimage and, on the
// FROZEN {"alg":"EdDSA"} protected header, returns the JWS signing input (the exact bytes
// the Ed25519 signature covers) and the raw 64-byte signature. It is the bridge from the
// §3.1 detached-JWS card path onto P1's raw-Ed25519 identity.VerifyObject: the JWS sig IS
// ed25519.Sign(key, signingInput), so verifying signingInput+rawSig with VerifyObject is
// exactly the §5.1 step-3 detached-JWS check — and it carries P1's anti-downgrade +
// as-of-time revocation grace (M5.1.2/M5.1.3) for free. ok=false ⇒ malformed/alg-substituted
// JWS ⇒ INVALID_SIGNATURE (a structural sig failure, not a parse-class MALFORMED_CARD).
func decodeDetachedJWS(preimage []byte, jws string) (signingInput, rawSig []byte, ok bool) {
	first := -1
	second := -1
	for i := 0; i < len(jws); i++ {
		if jws[i] == '.' {
			if first < 0 {
				first = i
			} else if second < 0 {
				second = i
			} else {
				return nil, nil, false // more than two dots
			}
		}
	}
	if first < 0 || second < 0 || second != first+1 {
		return nil, nil, false // not exactly two dots, or payload segment non-empty
	}
	hdrB64 := jws[:first]
	sigB64 := jws[second+1:]
	hdr, err := b64url.DecodeString(hdrB64)
	if err != nil || string(hdr) != string(jwsProtectedHeader) {
		return nil, nil, false // FROZEN header exact-match (no alg substitution)
	}
	sig, err := b64url.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, false
	}
	return []byte(hdrB64 + "." + b64url.EncodeToString(preimage)), sig, true
}

// ---- Sign (§2.6 + §5.1 self-publish default) ----

// Sign signs the card with controller ctrl under the adp-card profile (§2.6): it sets the
// envelope {signer_aid=ctrl.AID(), key_state_seq=ctrl.CurrentSeq(), alg=EdDSA, sig=detached JWS
// over Preimage()}. For self-publish, subject_did defaults to the signer when unset (§5.1 step 5).
//
// It reaches the controller's current key via identity.Controller.Sign(objPreimage), feeding it
// the JWS signing input (BASE64URL(header)"."BASE64URL(preimage)) so the controller's private key
// signs exactly the detached-JWS bytes a verifier recomputes. The controller also returns the
// key_state_seq a verifier MUST select (anti-downgrade), which becomes the envelope's seq.
func (c *AgentCard) Sign(ctrl *identity.Controller) error {
	if c.SubjectDID == "" {
		c.SubjectDID = ctrl.AID() // self-publish default (§5.1 step 5)
	}
	pre, err := c.Preimage() // envelope is excluded from the pre-image (§3.1), so its prior value is irrelevant
	if err != nil {
		return err
	}
	hdrB64, signingInput := jwsSigningInput(pre)
	sig, keyStateSeq := ctrl.Sign(signingInput)
	c.Envelope = EnvelopeJSON{
		SignerAID:   ctrl.AID(),
		KeyStateSeq: keyStateSeq,
		Alg:         AlgEdDSA,
		Sig:         assembleDetachedJWS(hdrB64, sig),
	}
	return nil
}

// SignWithKey signs the card with a raw Ed25519 key under the adp-card profile (§2.6), for the
// suite-test golden-vector path (_CONVENTIONS §8) and tests that do not hold a Controller.
// signerAID/keyStateSeq are written into the envelope verbatim.
func (c *AgentCard) SignWithKey(priv ed25519.PrivateKey, signerAID string, keyStateSeq uint64) error {
	if c.SubjectDID == "" {
		c.SubjectDID = signerAID
	}
	c.Envelope = EnvelopeJSON{}
	pre, err := c.Preimage()
	if err != nil {
		return err
	}
	c.Envelope = EnvelopeJSON{
		SignerAID:   signerAID,
		KeyStateSeq: keyStateSeq,
		Alg:         AlgEdDSA,
		Sig:         signDetachedJWS(priv, pre),
	}
	return nil
}

// ---- §2.3 CardTombstone ----

// CardTombstone is the §2.3 self-signed revoke object (profile adp-card, JSON/JCS): a CRDT
// LWW element keyed by subject_did, ordered by signed seq. The ONLY conformant revoke (§5.4):
// a delete admitted on a bare seq comparison without a subject-self-signed tombstone is
// non-conformant.
type CardTombstone struct {
	SubjectDID     string       `json:"subject_did"`      // MUST == signer's resolved identity
	Seq            uint64       `json:"seq"`              // MUST > high_water; in pre-image
	RevokedCardCID string       `json:"revoked_card_cid"` // the card_cid being tombstoned
	Reason         string       `json:"reason,omitempty"` // anr:adp.error-code label (§4.5)
	IssuedAt       int64        `json:"issued_at"`        // unix-s
	Envelope       EnvelopeJSON `json:"envelope"`
}

// preimageObject builds the tombstone's adp-card pre-image view: whole object minus the
// envelope and any legacy signature (§3.1; tombstones share the adp-card profile, §2.3).
func (t *CardTombstone) preimageObject() (map[string]any, error) {
	raw, err := json.Marshal(t)
	if err != nil {
		return nil, &Error{Code: MALFORMED_CARD, Detail: "tombstone not marshalable: " + err.Error()}
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, &Error{Code: MALFORMED_CARD, Detail: "tombstone not a JSON object: " + err.Error()}
	}
	delete(obj, "envelope")
	delete(obj, "signature")
	return obj, nil
}

// Preimage returns the tombstone's adp-card JCS pre-image (§3.1).
func (t *CardTombstone) Preimage() ([]byte, error) {
	obj, err := t.preimageObject()
	if err != nil {
		return nil, err
	}
	return jcsMarshal(obj)
}

// Sign signs the tombstone with controller ctrl (§5.4): self-signed by the subject. subject_did
// defaults to the signer when unset; the §5.4 gate enforces signer==subject on admission.
func (t *CardTombstone) Sign(ctrl *identity.Controller) error {
	if t.SubjectDID == "" {
		t.SubjectDID = ctrl.AID()
	}
	pre, err := t.Preimage()
	if err != nil {
		return err
	}
	hdrB64, signingInput := jwsSigningInput(pre)
	sig, keyStateSeq := ctrl.Sign(signingInput)
	t.Envelope = EnvelopeJSON{
		SignerAID:   ctrl.AID(),
		KeyStateSeq: keyStateSeq,
		Alg:         AlgEdDSA,
		Sig:         assembleDetachedJWS(hdrB64, sig),
	}
	return nil
}

// SignWithKey signs the tombstone with a raw Ed25519 key (suite-test / no-Controller path, §5.4).
func (t *CardTombstone) SignWithKey(priv ed25519.PrivateKey, signerAID string, keyStateSeq uint64) error {
	if t.SubjectDID == "" {
		t.SubjectDID = signerAID
	}
	t.Envelope = EnvelopeJSON{}
	pre, err := t.Preimage()
	if err != nil {
		return err
	}
	t.Envelope = EnvelopeJSON{
		SignerAID:   signerAID,
		KeyStateSeq: keyStateSeq,
		Alg:         AlgEdDSA,
		Sig:         signDetachedJWS(priv, pre),
	}
	return nil
}
