package a2acard

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode"

	"github.com/ANetResearch/ANetCore/identity"
)

// Resolver returns the KEL of aid. Verify calls it at most once, and only with the AID named by
// the card's anet-card extension after that AID has passed ParseKID's character check.
type Resolver func(aid string) ([]identity.SignedEvent, error)

// Skill is the part of an AgentSkill that a directory indexes.
type Skill struct {
	ID          string
	Name        string
	Description string
	Tags        []string
}

// Verified is the result of a successful Verify.
type Verified struct {
	// AID is the signing identity; it equals the anet-card params.aid and the kid AID.
	AID string
	// KeyStateSeq is the kid's key-state seq.
	KeyStateSeq uint64
	// Seq, IssuedAt and NotBefore are the anet-card params, parsed from decimal strings.
	// IssuedAt and NotBefore are unix milliseconds.
	Seq       uint64
	IssuedAt  uint64
	NotBefore uint64
	// PayloadHash is SHA-256 of the canonical payload (the card without "signatures"). Two
	// cards with the same PayloadHash make the same statement even if their signatures differ,
	// for example after the same card was re-signed under a rotated key.
	PayloadHash [32]byte
	Name        string
	Skills      []Skill
}

// Mark returns the high-water record a consumer stores for this card.
func (v *Verified) Mark() Mark { return Mark{Seq: v.Seq, PayloadHash: v.PayloadHash} }

// Verify admits an anet network card (A2A-DESIGN §10.3). now is unix milliseconds.
//
// Checks, in order; the first failure is returned as an *Error:
//  1. size: the card is at most MaxCardBytes;
//  2. strict I-JSON object (see Canonicalize);
//  3. "signatures" is a non-empty array of at most MaxSignatures {protected, signature} objects;
//  4. required members and limits: name (non-empty, <= MaxNameBytes), description
//     (<= MaxDescriptionBytes), version, supportedInterfaces (non-empty; url, protocolBinding,
//     protocolVersion), capabilities, defaultInputModes, defaultOutputModes, skills (1 to
//     MaxSkills; unique non-empty id; non-empty name and description; 1 to MaxTagsPerSkill
//     non-empty tags);
//  5. exactly one anet-card extension with params aid, seq, issuedAt and notBefore, the last
//     three canonical decimal strings;
//  6. every supportedInterfaces entry whose protocolBinding is BindingRelayURI has tenant == aid;
//  7. notBefore <= now + NotBeforeSkewMillis;
//  8. at least one signature whose protected header has alg EdDSA and kid
//     did:anet:<aid>#<seq>, where the KEL returned by resolve replays to aid, key state <seq>
//     has not been retired by a later rotation or deactivation (see CurrentKey), and the
//     Ed25519 signature verifies over the canonical payload.
//
// Step 2 also rejects an object, at any depth, with two member names that are equal under
// Unicode simple case folding, such as "tenant" and "Tenant". Go's encoding/json matches struct
// fields case-insensitively, so a consumer that decodes the stored bytes into a struct could
// otherwise read a member other than the one these checks examined.
//
// The structural checks (1-7) run before resolve is called, so a malformed or mis-bound card
// costs the verifier no KEL lookup. Signatures whose kid names another AID are rejected rather
// than resolved, for the same reason. If no signature passes and the KEL lookup failed, the
// CodeKELUnavailable error is returned: every signature naming the card's AID was left
// unchecked, so the card's validity is unknown even if another signature failed for a definite
// reason, and the caller should retry rather than record a rejection. Otherwise the error of
// the first signature is returned.
//
// Verify does not apply the params.seq high-water rule, which needs stored state; call
// CheckHighWater with the returned Mark.
func Verify(cardJSON []byte, resolve Resolver, now uint64) (*Verified, error) {
	if len(cardJSON) > MaxCardBytes {
		return nil, newErr(CodeTooLarge, fmt.Sprintf("card is %d bytes, limit %d", len(cardJSON), MaxCardBytes))
	}
	card, err := parseCard(cardJSON)
	if err != nil {
		return nil, err
	}
	if err := checkCaseDistinctNames(card); err != nil {
		return nil, err
	}
	sigs, err := signatureEntries(card)
	if err != nil {
		return nil, err
	}
	out := &Verified{}
	if err := checkRequired(card, out); err != nil {
		return nil, err
	}
	if err := readCardExtension(card, out); err != nil {
		return nil, err
	}
	if err := checkRelayTenants(card, out.AID); err != nil {
		return nil, err
	}
	if out.NotBefore > now && out.NotBefore-now > NotBeforeSkewMillis {
		return nil, newErr(CodeNotYetValid, fmt.Sprintf("notBefore %d is more than %d ms after now %d", out.NotBefore, NotBeforeSkewMillis, now))
	}
	payload, err := canonicalPayload(card)
	if err != nil {
		return nil, err
	}

	kels := &kelOnce{resolve: resolve}
	var firstErr error
	for _, sig := range sigs {
		ks, err := verifyAnetSignature(sig, payload, out.AID, kels)
		if err == nil {
			out.KeyStateSeq = ks
			out.PayloadHash = sha256.Sum256(payload)
			return out, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if kels.err != nil {
		return nil, kels.err
	}
	return nil, firstErr
}

// kelOnce calls the resolver at most once per Verify and remembers the result, including an
// error, so a card with several signatures does not trigger several lookups.
type kelOnce struct {
	resolve Resolver
	done    bool
	kel     []identity.SignedEvent
	err     error
}

func (k *kelOnce) get(aid string) ([]identity.SignedEvent, error) {
	if !k.done {
		k.done = true
		if k.resolve == nil {
			k.err = newErr(CodeKELUnavailable, "no resolver")
		} else if kel, err := k.resolve(aid); err != nil {
			k.err = &Error{Code: CodeKELUnavailable, Detail: "resolving KEL of " + aid, Err: err}
		} else {
			k.kel = kel
		}
	}
	return k.kel, k.err
}

// verifyAnetSignature checks one signature entry against the card AID and returns the kid's
// key-state seq.
func verifyAnetSignature(sig Signature, payload []byte, aid string, kels *kelOnce) (uint64, error) {
	hdr, err := parseHeader(sig.Protected)
	if err != nil {
		return 0, err
	}
	kidAID, ksSeq, err := ParseKID(hdr.Kid)
	if err != nil {
		return 0, err
	}
	if kidAID != aid {
		return 0, newErr(CodeBindingMismatch, "kid AID "+kidAID+" is not the anet-card params.aid "+aid)
	}
	kel, err := kels.get(aid)
	if err != nil {
		return 0, err
	}
	pub, err := currentKey(kel, aid, ksSeq)
	if err != nil {
		return 0, err
	}
	if err := verifyEd25519(pub, sig, payload); err != nil {
		return 0, err
	}
	return ksSeq, nil
}

// CurrentKey returns the public key named by kid, provided kid is did:anet:<AID>#<seq>, kel
// replays to AID, and key state <seq> is current (see below). A KeyResolver for a2a-go can be
// built on it: fetch the KEL for the kid's AID, then call CurrentKey.
//
// A key state is current when no rotation or deactivation event follows it in the KEL. The
// states from the last rotation (or the inception) to the end of the KEL are therefore all
// current and share one key: ixn and drt events advance the key-state seq without changing
// the signing key, and a card signed before such an event was signed by the key that is still
// in force. JWKS lists exactly these states. A deactivated KEL has no current state. A card
// signed under a rotated key is rejected with no grace period: a card is a statement about the
// present, unlike an envelope whose signing time can be bounded.
func CurrentKey(kid string, kel []identity.SignedEvent) (ed25519.PublicKey, error) {
	aid, seq, err := ParseKID(kid)
	if err != nil {
		return nil, err
	}
	return currentKey(kel, aid, seq)
}

func currentKey(kel []identity.SignedEvent, aid string, seq uint64) (ed25519.PublicKey, error) {
	states, err := identity.Replay(kel)
	if err != nil {
		return nil, &Error{Code: CodeUnknownAID, Detail: "KEL does not replay", Err: err}
	}
	if got := states[len(states)-1].AID; got != aid {
		return nil, newErr(CodeUnknownAID, "KEL replays to "+got+", not "+aid)
	}
	lo, ok := currentRange(kel)
	if !ok {
		return nil, newErr(CodeKeyNotCurrent, "AID is deactivated")
	}
	if seq >= uint64(len(states)) {
		return nil, newErr(CodeKeyNotCurrent, fmt.Sprintf("key-state seq %d is beyond the KEL (length %d)", seq, len(states)))
	}
	if seq < uint64(lo) {
		return nil, newErr(CodeKeyNotCurrent, fmt.Sprintf("key-state seq %d was retired by the rotation at seq %d", seq, lo))
	}
	keys := states[seq].CurrentKeys
	if len(keys) != 1 || len(keys[0]) != ed25519.PublicKeySize {
		return nil, newErr(CodeKeyNotCurrent, "key state does not hold exactly one Ed25519 key")
	}
	return ed25519.PublicKey(keys[0]), nil
}

// currentRange returns the index of the first current key state; states lo..len(kel)-1 are
// current. ok is false when the KEL ends in a deactivation. The KEL must already have passed
// identity.Replay, which guarantees that index i holds seq i.
//
// The rule is computed from the event types rather than from KeyState.Status so that it does
// not depend on how Replay's post-pass propagates retirement across ixn and drt events.
func currentRange(kel []identity.SignedEvent) (lo int, ok bool) {
	for i := len(kel) - 1; i > 0; i-- {
		switch kel[i].Event.Type {
		case identity.Deactivation:
			return 0, false
		case identity.Rotation:
			return i, true
		}
	}
	return 0, true
}

func signatureEntries(card *value) ([]Signature, error) {
	sv, ok := card.member("signatures")
	if !ok || (sv.kind == kindArray && len(sv.arr) == 0) {
		return nil, newErr(CodeUnsigned, "card has no signatures")
	}
	if sv.kind != kindArray {
		return nil, newErr(CodeInvalidCard, "signatures is not an array")
	}
	if len(sv.arr) > MaxSignatures {
		return nil, newErr(CodeTooLarge, fmt.Sprintf("%d signatures, limit %d", len(sv.arr), MaxSignatures))
	}
	out := make([]Signature, 0, len(sv.arr))
	for i, e := range sv.arr {
		p, err := str(e, "protected", true)
		if err != nil {
			return nil, prefixed(err, fmt.Sprintf("signatures[%d]", i))
		}
		s, err := str(e, "signature", true)
		if err != nil {
			return nil, prefixed(err, fmt.Sprintf("signatures[%d]", i))
		}
		out = append(out, Signature{Protected: p, Signature: s})
	}
	return out, nil
}

func checkRequired(card *value, out *Verified) error {
	name, err := str(card, "name", true)
	if err != nil {
		return err
	}
	if len(name) > MaxNameBytes {
		return newErr(CodeTooLarge, fmt.Sprintf("name is %d bytes, limit %d", len(name), MaxNameBytes))
	}
	out.Name = name
	desc, err := str(card, "description", false)
	if err != nil {
		return err
	}
	if len(desc) > MaxDescriptionBytes {
		return newErr(CodeTooLarge, fmt.Sprintf("description is %d bytes, limit %d", len(desc), MaxDescriptionBytes))
	}
	if _, err := str(card, "version", false); err != nil {
		return err
	}
	ifaces, err := arr(card, "supportedInterfaces", true)
	if err != nil {
		return err
	}
	for i, it := range ifaces {
		for _, f := range []struct {
			name     string
			nonEmpty bool
		}{{"url", true}, {"protocolBinding", true}, {"protocolVersion", false}} {
			if _, err := str(it, f.name, f.nonEmpty); err != nil {
				return prefixed(err, fmt.Sprintf("supportedInterfaces[%d]", i))
			}
		}
	}
	if _, err := obj(card, "capabilities"); err != nil {
		return err
	}
	for _, f := range []string{"defaultInputModes", "defaultOutputModes"} {
		if _, err := strList(card, f, false); err != nil {
			return err
		}
	}
	skills, err := arr(card, "skills", true)
	if err != nil {
		return err
	}
	if len(skills) > MaxSkills {
		return newErr(CodeTooLarge, fmt.Sprintf("%d skills, limit %d", len(skills), MaxSkills))
	}
	seen := make(map[string]bool, len(skills))
	out.Skills = make([]Skill, 0, len(skills))
	for i, sk := range skills {
		s, err := readSkill(sk)
		if err != nil {
			return prefixed(err, fmt.Sprintf("skills[%d]", i))
		}
		if len(s.Tags) > MaxTagsPerSkill {
			return newErr(CodeTooLarge, fmt.Sprintf("skills[%d] has %d tags, limit %d", i, len(s.Tags), MaxTagsPerSkill))
		}
		if seen[s.ID] {
			// A2A defines id as the skill's unique identifier; a directory keyed by skill id
			// cannot index two skills under one id.
			return newErr(CodeInvalidCard, fmt.Sprintf("skills[%d]: duplicate id %q", i, s.ID))
		}
		seen[s.ID] = true
		out.Skills = append(out.Skills, s)
	}
	return nil
}

func readSkill(sk *value) (Skill, error) {
	var s Skill
	var err error
	if s.ID, err = str(sk, "id", true); err != nil {
		return s, err
	}
	if s.Name, err = str(sk, "name", true); err != nil {
		return s, err
	}
	if s.Description, err = str(sk, "description", true); err != nil {
		return s, err
	}
	s.Tags, err = strList(sk, "tags", true)
	return s, err
}

// readCardExtension finds the anet-card extension and fills AID, Seq, IssuedAt and NotBefore.
func readCardExtension(card *value, out *Verified) error {
	caps, _ := card.member("capabilities") // presence and type checked by checkRequired
	exts, ok := caps.member("extensions")
	if !ok {
		return newErr(CodeInvalidCard, "capabilities.extensions is missing (the anet-card extension is required)")
	}
	if exts.kind != kindArray {
		return newErr(CodeInvalidCard, "capabilities.extensions is not an array")
	}
	var params *value
	for i, e := range exts.arr {
		uri, err := str(e, "uri", false)
		if err != nil {
			return prefixed(err, fmt.Sprintf("capabilities.extensions[%d]", i))
		}
		if uri != ExtCardURI {
			continue
		}
		if params != nil {
			return newErr(CodeInvalidCard, "more than one anet-card extension")
		}
		if params, err = obj(e, "params"); err != nil {
			return prefixed(err, "anet-card extension")
		}
	}
	if params == nil {
		return newErr(CodeInvalidCard, "no anet-card extension ("+ExtCardURI+")")
	}
	aid, err := str(params, "aid", true)
	if err != nil {
		return prefixed(err, "anet-card params")
	}
	out.AID = aid
	for _, f := range []struct {
		name string
		dst  *uint64
	}{{"seq", &out.Seq}, {"issuedAt", &out.IssuedAt}, {"notBefore", &out.NotBefore}} {
		s, err := str(params, f.name, true)
		if err != nil {
			// Includes a JSON number: above 2^53 a number loses precision in binary64 (and so
			// in the canonical form), which is why A2A-DESIGN §10.1 carries these as strings.
			return prefixed(err, "anet-card params")
		}
		n, ok := parseDecimal(s)
		if !ok {
			return newErr(CodeInvalidCard, "anet-card params."+f.name+" is not a canonical decimal string")
		}
		*f.dst = n
	}
	return nil
}

func checkRelayTenants(card *value, aid string) error {
	ifaces, _ := card.member("supportedInterfaces") // checked by checkRequired
	for i, it := range ifaces.arr {
		b, _ := it.member("protocolBinding")
		if b.str != BindingRelayURI {
			continue
		}
		t, ok := it.member("tenant")
		if !ok || t.kind != kindString || t.str != aid {
			return newErr(CodeBindingMismatch, fmt.Sprintf("supportedInterfaces[%d] is an anet relay interface whose tenant is not %s", i, aid))
		}
	}
	return nil
}

// checkCaseDistinctNames rejects an object, at any depth, that has two member names equal under
// Unicode simple case folding, for example "tenant" and "Tenant".
//
// RFC 8785 and I-JSON treat such names as distinct, so the signature covers both members. Go's
// encoding/json, however, matches struct fields case-insensitively (bytes.EqualFold) and keeps
// the last match in document order, and the stored card bytes may order members freely. Verify
// reads the exact-case member; a consumer that decodes the same bytes into a struct (a2a-go's
// AgentCard, or the daemon's and hub's card types) can read the other. For example, a relay
// interface carrying "protocolBinding":"JSONRPC" and, after it, "PROTOCOLBINDING" set to the
// relay binding passes the tenant check here while a2a-go reads a relay interface whose tenant
// is another AID. The A2A member names are distinct under case folding, so a card that follows
// the schema is not affected; the cost is that a card with case-variant names inside
// free-form members (extension params, metadata) is rejected too.
func checkCaseDistinctNames(v *value) error {
	switch v.kind {
	case kindArray:
		for _, e := range v.arr {
			if err := checkCaseDistinctNames(e); err != nil {
				return err
			}
		}
	case kindObject:
		seen := make(map[string]string, len(v.obj))
		// Sorted order makes the reported pair independent of map iteration order.
		for _, name := range sortedNames(v.obj) {
			f := foldName(name)
			if other, dup := seen[f]; dup {
				return newErr(CodeInvalidCard, fmt.Sprintf("member names %q and %q differ only in letter case", other, name))
			}
			seen[f] = name
			if err := checkCaseDistinctNames(v.obj[name]); err != nil {
				return err
			}
		}
	}
	return nil
}

// foldName maps each rune to the smallest rune of its unicode.SimpleFold orbit, so that
// foldName(a) == foldName(b) exactly when strings.EqualFold(a, b), the comparison
// encoding/json applies to struct field names.
func foldName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		for {
			r2 := unicode.SimpleFold(r)
			if r2 <= r {
				r = r2
				break
			}
			r = r2
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Accessors. Each returns CodeInvalidCard naming the member on a missing member or wrong type.

func str(v *value, name string, nonEmpty bool) (string, error) {
	if v == nil || v.kind != kindObject {
		return "", newErr(CodeInvalidCard, "not an object")
	}
	m, ok := v.member(name)
	if !ok {
		return "", newErr(CodeInvalidCard, name+" is missing")
	}
	if m.kind != kindString {
		return "", newErr(CodeInvalidCard, name+" is not a string")
	}
	if nonEmpty && m.str == "" {
		return "", newErr(CodeInvalidCard, name+" is empty")
	}
	return m.str, nil
}

func obj(v *value, name string) (*value, error) {
	m, ok := v.member(name)
	if !ok {
		return nil, newErr(CodeInvalidCard, name+" is missing")
	}
	if m.kind != kindObject {
		return nil, newErr(CodeInvalidCard, name+" is not an object")
	}
	return m, nil
}

func arr(v *value, name string, nonEmpty bool) ([]*value, error) {
	if v == nil || v.kind != kindObject {
		return nil, newErr(CodeInvalidCard, "not an object")
	}
	m, ok := v.member(name)
	if !ok {
		return nil, newErr(CodeInvalidCard, name+" is missing")
	}
	if m.kind != kindArray {
		return nil, newErr(CodeInvalidCard, name+" is not an array")
	}
	if nonEmpty && len(m.arr) == 0 {
		return nil, newErr(CodeInvalidCard, name+" is empty")
	}
	return m.arr, nil
}

// strList reads an array of strings. With nonEmpty, the array and each element must be non-empty.
func strList(v *value, name string, nonEmpty bool) ([]string, error) {
	a, err := arr(v, name, nonEmpty)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(a))
	for i, e := range a {
		if e.kind != kindString {
			return nil, newErr(CodeInvalidCard, fmt.Sprintf("%s[%d] is not a string", name, i))
		}
		if nonEmpty && e.str == "" {
			return nil, newErr(CodeInvalidCard, fmt.Sprintf("%s[%d] is empty", name, i))
		}
		out = append(out, e.str)
	}
	return out, nil
}

func prefixed(err error, where string) error {
	if e, ok := err.(*Error); ok {
		return &Error{Code: e.Code, Detail: where + ": " + e.Detail, Err: e.Err}
	}
	return err
}
