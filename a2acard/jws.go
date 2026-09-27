package a2acard

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/ANetResearch/ANetCore/identity"
)

// b64 is base64url without padding (RFC 7515 §2). Strict decoding rejects non-zero trailing
// bits. Decode through decodeB64, which also rejects the line breaks that encoding/base64
// skips; together the two rules give each byte string exactly one accepted encoding.
var b64 = base64.RawURLEncoding.Strict()

// decodeB64 decodes unpadded base64url and accepts only the 64 characters of the base64url
// alphabet. encoding/base64 ignores '\r' and '\n' even in strict mode, so without this check a
// signature string with inserted line breaks decodes to the same bytes and still verifies:
// a relaying party could then store and serve a second byte form of a signed card. a2a-go
// decodes leniently and accepts such strings; rejecting them here only refuses spellings that
// no conforming signer produces.
func decodeB64(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return nil, errors.New("character outside the base64url alphabet")
		}
	}
	return b64.DecodeString(s)
}

// Signature is one entry of an AgentCard's "signatures" array (A2A §4.4.7). The optional
// unprotected "header" member is not represented: it is not covered by the signature, and
// this package never reads it.
type Signature struct {
	Protected string `json:"protected"`
	Signature string `json:"signature"`
}

// Header is the decoded JWS protected header.
type Header struct {
	Alg string
	Kid string
	Jku string
	Typ string
}

// KID returns the kid for key state seq of aid: "did:anet:<AID>#<seq>".
func KID(aid string, seq uint64) string {
	return KIDPrefix + aid + "#" + strconv.FormatUint(seq, 10)
}

// ParseKID splits a kid of the form did:anet:<AID>#<seq>. The AID must be 1-128 characters of
// [a-z0-9] (the character set of the base32 CIDs that identity derives) and seq a decimal
// without leading zeros. The AID character check exists because a resolver may place the AID in
// a URL path; the AID itself is authenticated later by replaying its KEL.
func ParseKID(kid string) (aid string, seq uint64, err error) {
	rest, ok := strings.CutPrefix(kid, KIDPrefix)
	if !ok {
		return "", 0, newErr(CodeBadHeader, "kid is not a did:anet identifier")
	}
	aid, seqStr, ok := strings.Cut(rest, "#")
	if !ok {
		return "", 0, newErr(CodeBadHeader, "kid has no #<key-state-seq> fragment")
	}
	if !validAID(aid) {
		return "", 0, newErr(CodeBadHeader, "kid AID is empty, too long or has characters outside [a-z0-9]")
	}
	seq, ok = parseDecimal(seqStr)
	if !ok {
		return "", 0, newErr(CodeBadHeader, "kid key-state seq is not a canonical decimal")
	}
	return aid, seq, nil
}

func validAID(aid string) bool {
	if aid == "" || len(aid) > 128 {
		return false
	}
	for i := 0; i < len(aid); i++ {
		c := aid[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// parseDecimal accepts the canonical decimal form of a uint64: digits only, no sign, no
// leading zeros except "0" itself. A value has exactly one accepted spelling, so two cards
// cannot carry the same seq under different strings.
func parseDecimal(s string) (uint64, bool) {
	if s == "" || len(s) > 20 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

// SigningPayload returns the A2A §8.4.1 JWS payload for a card (FormProtoStripped): the card
// with its top-level "signatures" member removed and the members that proto3 field presence
// treats as unset removed (see stripDefaults), in RFC 8785 form. This is the payload Sign signs
// and Verify checks first. The card must be a JSON object. For a card in publish form it equals
// RawSigningPayload.
func SigningPayload(cardJSON []byte) ([]byte, error) {
	card, err := parseCard(cardJSON)
	if err != nil {
		return nil, err
	}
	return canonicalPayload(stripDefaults(card, schemaAgentCard))
}

// RawSigningPayload returns the FormRaw payload: the RFC 8785 form of the card with only its
// top-level "signatures" member removed. This is the payload a2a-go signs and verifies.
func RawSigningPayload(cardJSON []byte) ([]byte, error) {
	card, err := parseCard(cardJSON)
	if err != nil {
		return nil, err
	}
	return canonicalPayload(card)
}

func parseCard(cardJSON []byte) (*value, error) {
	card, err := parseJSON(cardJSON)
	if err != nil {
		return nil, err
	}
	if card.kind != kindObject {
		return nil, newErr(CodeInvalidCard, "card is not a JSON object")
	}
	return card, nil
}

func canonicalPayload(card *value) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, card, "signatures"); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// signingInput is ASCII(BASE64URL(protected header)) "." BASE64URL(payload) (RFC 7515 §5.1).
// protectedB64 is used exactly as it appears in the card: the signature covers those
// characters, not a re-serialization of the decoded header.
func signingInput(protectedB64 string, payload []byte) []byte {
	out := make([]byte, 0, len(protectedB64)+1+b64.EncodedLen(len(payload)))
	out = append(out, protectedB64...)
	out = append(out, '.')
	return b64.AppendEncode(out, payload)
}

// Sign signs cardJSON with priv and returns the card with the new signature appended to its
// "signatures" array (existing entries are kept).
//
// cardJSON must be in publish form (CheckPublishForm); otherwise Sign returns the
// CodeNotPublishForm error naming the first offending member and signs nothing. Sign does not
// rewrite the card into that form: dropping a member the builder wrote, such as an empty
// REQUIRED description, would publish a card other than the one the builder meant, and some
// violations (an empty skill description, an unknown member) have no correct automatic repair.
// The card builder emits the publish form directly. On a card in publish form the
// proto-stripped and the raw payload are the same bytes, so the signature verifies under the
// A2A specification's rule, a2a-python and a2a-go alike.
//
// The protected header is {"alg":"EdDSA","jku":jku,"kid":kid,"typ":"JOSE"}, with jku omitted
// when empty. It is serialized with encoding/json from a map, which sorts the keys and applies
// Go's HTML escaping to the values; this is the serialization a2a-go's Signer uses (and, for
// these values, PyJWT's), so they produce the same bytes and, Ed25519 being deterministic, the
// same signature for the same card and key.
//
// The returned card is the RFC 8785 form of the whole card including "signatures". Member
// order of the input is therefore not preserved, and numbers are printed in their canonical
// form, so the returned bytes show exactly the values the signature covers.
//
// Sign does not check anet network card rules (see Verify): it also signs the proxy cards of
// the local A2A interface, which carry no anet-card extension. Use SignWithController to sign
// under an identity's current key state.
func Sign(cardJSON []byte, priv ed25519.PrivateKey, kid, jku string) ([]byte, error) {
	return sign(cardJSON, priv, kid, jku, true)
}

// sign implements Sign. With checkForm false it signs any JSON object over its proto-stripped
// payload, as a signer that follows A2A §8.4.1 without enforcing the publish form would; the
// tests use that to build cards that only Verify's own checks reject.
func sign(cardJSON []byte, priv ed25519.PrivateKey, kid, jku string, checkForm bool) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, newErr(CodeBadHeader, "private key is not an Ed25519 private key")
	}
	if kid == "" {
		return nil, newErr(CodeBadHeader, "kid is empty")
	}
	card, err := parseCard(cardJSON)
	if err != nil {
		return nil, err
	}
	sigs, present := card.member("signatures")
	if present && sigs.kind != kindArray {
		return nil, newErr(CodeInvalidCard, "signatures is not an array")
	}
	if checkForm {
		if err := checkPublishForm(card); err != nil {
			return nil, err
		}
	}
	payload, err := canonicalPayload(stripDefaults(card, schemaAgentCard))
	if err != nil {
		return nil, err
	}
	return appendSignature(card, sigs, present, priv, kid, jku, payload)
}

// appendSignature signs payload under a new protected header and returns the canonical card
// with the signature entry appended.
func appendSignature(card, sigs *value, present bool, priv ed25519.PrivateKey, kid, jku string, payload []byte) ([]byte, error) {
	hdr := map[string]string{"alg": AlgEdDSA, "kid": kid, "typ": TypJOSE}
	if jku != "" {
		hdr["jku"] = jku
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	protected := b64.EncodeToString(hdrJSON)
	sig := ed25519.Sign(priv, signingInput(protected, payload))

	entry := &value{kind: kindObject, obj: map[string]*value{
		"protected": {kind: kindString, str: protected},
		"signature": {kind: kindString, str: b64.EncodeToString(sig)},
	}}
	if !present {
		sigs = &value{kind: kindArray}
		card.obj["signatures"] = sigs
	}
	sigs.arr = append(sigs.arr, entry)

	var buf bytes.Buffer
	if err := writeCanonical(&buf, card, ""); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SignWithController signs cardJSON with c's current key under kid did:anet:<AID>#<current seq>.
func SignWithController(cardJSON []byte, c *identity.Controller, jku string) ([]byte, error) {
	return Sign(cardJSON, c.CurrentPrivateKey(), KID(c.AID(), c.CurrentSeq()), jku)
}

// VerifySignature checks one JWS signature over cardJSON against pub, with no anet rules: the
// A2A §8.4.3 procedure for a key the caller already trusts. alg must be EdDSA and the header
// must not carry crit. The signature is checked over the proto-stripped payload and, if that
// fails, over the raw payload (see Verify). It returns the decoded protected header.
func VerifySignature(cardJSON []byte, sig Signature, pub ed25519.PublicKey) (*Header, error) {
	hdr, _, err := VerifySignatureForm(cardJSON, sig, pub)
	return hdr, err
}

// VerifySignatureForm is VerifySignature that also reports the payload form under which the
// signature verified.
func VerifySignatureForm(cardJSON []byte, sig Signature, pub ed25519.PublicKey) (*Header, CanonicalForm, error) {
	card, err := parseCard(cardJSON)
	if err != nil {
		return nil, "", err
	}
	stripped, raw, err := payloads(card)
	if err != nil {
		return nil, "", err
	}
	hdr, err := parseHeader(sig.Protected)
	if err != nil {
		return nil, "", err
	}
	form, err := verifyForms(pub, sig, stripped, raw)
	if err != nil {
		return nil, "", err
	}
	return hdr, form, nil
}

// verifyForms checks sig over the proto-stripped payload and then, when the raw payload is
// different, over the raw one.
func verifyForms(pub ed25519.PublicKey, sig Signature, stripped, raw []byte) (CanonicalForm, error) {
	err := verifyEd25519(pub, sig, stripped)
	if err == nil {
		return FormProtoStripped, nil
	}
	if !IsCode(err, CodeInvalidSignature) || bytes.Equal(stripped, raw) {
		return "", err
	}
	if verifyEd25519(pub, sig, raw) == nil {
		return FormRaw, nil
	}
	return "", newErr(CodeInvalidSignature, "Ed25519 verification failed over both the proto-stripped and the raw payload")
}

func verifyEd25519(pub ed25519.PublicKey, sig Signature, payload []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return newErr(CodeInvalidSignature, "public key is not an Ed25519 public key")
	}
	raw, err := decodeB64(sig.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return newErr(CodeInvalidSignature, "signature is not a base64url-encoded 64-byte value")
	}
	if !ed25519.Verify(pub, signingInput(sig.Protected, payload), raw) {
		return newErr(CodeInvalidSignature, "Ed25519 verification failed")
	}
	return nil
}

// parseHeader decodes and checks a protected header. It uses the strict parser, so a header
// with duplicate names (which other JSON libraries resolve differently) is rejected.
func parseHeader(protected string) (*Header, error) {
	raw, err := decodeB64(protected)
	if err != nil {
		return nil, newErr(CodeBadHeader, "protected header is not base64url")
	}
	v, err := parseJSON(raw)
	if err != nil {
		return nil, &Error{Code: CodeBadHeader, Detail: "protected header is not I-JSON", Err: err}
	}
	if v.kind != kindObject {
		return nil, newErr(CodeBadHeader, "protected header is not a JSON object")
	}
	var h Header
	for name, dst := range map[string]*string{"alg": &h.Alg, "kid": &h.Kid, "jku": &h.Jku, "typ": &h.Typ} {
		m, ok := v.member(name)
		if !ok {
			continue
		}
		if m.kind != kindString {
			return nil, newErr(CodeBadHeader, name+" is not a string")
		}
		*dst = m.str
	}
	if h.Alg != AlgEdDSA {
		return nil, newErr(CodeBadHeader, "alg is "+strconv.Quote(h.Alg)+", only EdDSA is accepted")
	}
	if _, ok := v.member("crit"); ok {
		// RFC 7515 §4.1.11: a recipient that does not understand every listed extension must
		// reject. This package understands none.
		return nil, newErr(CodeBadHeader, "crit is not supported")
	}
	return &h, nil
}
