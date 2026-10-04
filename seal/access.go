package seal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/ANetResearch/ANetCore/coredet"
)

// CapType is key 0 of a CapBody, the type tag the mailbox signing key signs
// under (core §3.2 L6). A capability body has no extension keys, so another
// version of the object is another tag.
const CapType = "anet.cap/1"

// Capability classes, CapBody key 4. The issuer chooses the class by its
// relation to the holder; the hub applies the class's rate and quota.
const (
	// CapClassContact is a capability for a peer the issuer knows (contact).
	CapClassContact uint64 = 1
	// CapClassStranger is a capability for anyone else (stranger): it counts
	// against the recipient's non-contact share of the mailbox.
	CapClassStranger uint64 = 2
)

// CapIDLen is the length of a capability id, CapBody key 3.
const CapIDLen = 16

// The window a verifier accepts cap_exp in (core §2.1):
//
//	now - CapExpGraceMS <= cap_exp <= now + CapExpMaxAheadMS.
//
// The grace absorbs clock skew between issuer and verifier; the bound ahead is
// one day over the longest lifetime an issuer writes (30 days for a contact
// peer capability, SSR-W4), so a capability cannot be made to outlive the
// rotation of the key that signed it by much.
const (
	CapExpGraceMS    = 5 * minuteMS
	CapExpMaxAheadMS = 31 * dayMS
)

// accessLabel is the prefix of the holder's proof of possession (core §3.2
// L5, a B-class input: the label, 0x00, then fixed-length fields).
const accessLabel = "anet-access/v2\x00"

// CapBody is what a capability says (core §2.1): who issued it (owner, the
// only recipient it delivers to), under which mailbox-key epoch, its id,
// class and expiry, and the public half of the holder key that proves
// possession. Cap.Body is its CoreDet encoding and the mailbox signing key
// signs those bytes (L6). Nothing in it names the holder's AID: a hub that
// admits a delivery under it learns the recipient, not the sender.
//
//anet:wire CapBody
type CapBody struct {
	Type   string `cbor:"0,keyasint"` // CapType
	Owner  string `cbor:"1,keyasint"` // issuer AID; equals the outer to of every envelope it admits
	Epoch  uint64 `cbor:"2,keyasint"` // the owner's mbox.epoch when signed, >= 1
	CapID  []byte `cbor:"3,keyasint"` // CapIDLen random bytes
	Class  uint64 `cbor:"4,keyasint"` // CapClassContact or CapClassStranger
	CapExp uint64 `cbor:"5,keyasint"` // expiry, unix ms
	Holder []byte `cbor:"6,keyasint"` // holder Ed25519 public key, new for every capability
}

// capBodyKeys are the keys of a CapBody, all required, by number.
var capBodyKeys = [...]string{0: "t", 1: "owner", 2: "epoch", 3: "cap_id", 4: "class", 5: "cap_exp", 6: "holder"}

// Marshal returns the CoreDet encoding of b: the bytes Cap.Body carries and
// the mailbox key signs.
func (b *CapBody) Marshal() ([]byte, error) { return coredet.Marshal(*b) }

// decodeCapBody is the strict decode of Cap.Body (SSR-W3): a map with exactly
// the keys 0-6 (no extension range, CORE-E3), each of its type, cap_id
// CapIDLen bytes and holder an Ed25519 public key; and the bytes must be the
// CoreDet encoding of what they decode to (CORE-E2), so one capability has one
// encoding. It does not judge the values: the type tag, the epoch and the
// class are steps of their own in VerifyAccess and CheckGrant.
func decodeCapBody(b []byte) (*CapBody, error) {
	m, err := decodeFields(b)
	if err != nil {
		return nil, fmt.Errorf("cap body: %w", err)
	}
	if k, ok := firstUnknownKey(m, uint64(len(capBodyKeys))); ok {
		return nil, fmt.Errorf("cap body has key %d, which %s does not name", k, CapType)
	}
	var c CapBody
	var errs []error
	text := func(k uint64, dst *string) {
		v, err := rawText(m, k)
		*dst = v
		errs = append(errs, err)
	}
	unum := func(k uint64, dst *uint64) {
		v, err := rawUint(m, k)
		*dst = v
		errs = append(errs, err)
	}
	byts := func(k uint64, dst *[]byte) {
		v, err := rawBytes(m, k)
		*dst = v
		errs = append(errs, err)
	}
	text(0, &c.Type)
	text(1, &c.Owner)
	unum(2, &c.Epoch)
	byts(3, &c.CapID)
	unum(4, &c.Class)
	unum(5, &c.CapExp)
	byts(6, &c.Holder)
	for k, err := range errs { // errs[k] is the result for key k
		if err != nil {
			return nil, fmt.Errorf("cap body %s: %w", capBodyKeys[k], err)
		}
	}
	switch {
	case len(c.CapID) != CapIDLen:
		return nil, fmt.Errorf("cap body cap_id is %d bytes, want %d", len(c.CapID), CapIDLen)
	case len(c.Holder) != ed25519.PublicKeySize:
		return nil, fmt.Errorf("cap body holder is %d bytes, want %d", len(c.Holder), ed25519.PublicKeySize)
	}
	re, err := c.Marshal()
	if err != nil {
		return nil, fmt.Errorf("cap body: re-encode: %w", err)
	}
	if !bytes.Equal(re, b) {
		return nil, errors.New("cap body is not the CoreDet encoding of its content (CORE-E2)")
	}
	return &c, nil
}

// UnmarshalCapBody decodes Cap.Body strictly (decodeCapBody). A failure is
// access-invalid with Detail "decode", the step VerifyAccess reports for it.
func UnmarshalCapBody(b []byte) (*CapBody, error) {
	c, err := decodeCapBody(b)
	if err != nil {
		return nil, failWrap(ReasonAccessInvalid, err, "decode")
	}
	return c, nil
}

// decodeCap is the structural decode of a Cap as carried in outer key 7 and in
// a Grant: a map with no key but 1 and 2 (Cap has no extension range, CORE-E3),
// a byte string body and a SigLen-byte sig. The body itself is decoded by
// decodeCapBody.
func decodeCap(raw []byte) (*Cap, error) {
	m, err := decodeFields(raw)
	if err != nil {
		return nil, fmt.Errorf("cap: %w", err)
	}
	if k, ok := firstKeyOutside(m, 1, 2); ok {
		return nil, fmt.Errorf("cap has key %d", k)
	}
	var c Cap
	if c.Body, err = rawBytes(m, 1); err != nil {
		return nil, fmt.Errorf("cap body: %w", err)
	}
	if c.Sig, err = rawBytes(m, 2); err != nil {
		return nil, fmt.Errorf("cap sig: %w", err)
	}
	if len(c.Sig) != SigLen {
		return nil, fmt.Errorf("cap sig is %d bytes, want %d", len(c.Sig), SigLen)
	}
	return &c, nil
}

// UnmarshalCap decodes the wire form of a capability, for instance one a
// daemon stored from a grant. It checks the structure (access-invalid, Detail
// "parse", as ParseOuter reports it); VerifyAccess checks the content.
func UnmarshalCap(b []byte) (*Cap, error) {
	c, err := decodeCap(b)
	if err != nil {
		return nil, failWrap(ReasonAccessInvalid, err, "parse")
	}
	return c, nil
}

// Marshal returns the CoreDet encoding of c, the form a Grant and outer key 7
// carry. A c ParseOuter would refuse (a sig that is not SigLen bytes) is
// invalid-input.
func (c *Cap) Marshal() ([]byte, error) {
	if c == nil {
		return nil, fail(ReasonInvalidInput, "nil cap")
	}
	b, err := coredet.Marshal(*c)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "encode cap")
	}
	if _, err := decodeCap(b); err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "cap")
	}
	return b, nil
}

// firstKeyOutside returns the smallest key of m outside [lo, hi], if there is
// one. The smallest is reported so the error text does not depend on map
// iteration order.
func firstKeyOutside(m fieldMap, lo, hi uint64) (uint64, bool) {
	found := false
	var least uint64
	for k := range m {
		if (k < lo || k > hi) && (!found || k < least) {
			least, found = k, true
		}
	}
	return least, found
}

// checkIssue applies to a CapBody about to be signed every rule a verifier
// applies to the body alone, so an issuer cannot sign a capability that every
// verifier refuses: the type tag, an owner (an AID: not empty, no U+0000), an
// epoch of at least 1, a CapIDLen-byte id, a known class, an expiry and an
// Ed25519 holder key. Whether cap_exp is in the window depends on when it is
// used; SSR-W4 sets how far ahead an issuer writes it.
func (b *CapBody) checkIssue() error {
	switch {
	case b.Type != CapType:
		return fmt.Errorf("type %q, want %q", b.Type, CapType)
	case b.Owner == "" || strings.IndexByte(b.Owner, 0) >= 0:
		return errors.New("owner must be an AID: not empty, no U+0000")
	case b.Epoch == 0:
		return errors.New("epoch 0; a mailbox key's epoch starts at 1")
	case len(b.CapID) != CapIDLen:
		return fmt.Errorf("cap_id is %d bytes, want %d", len(b.CapID), CapIDLen)
	case b.Class != CapClassContact && b.Class != CapClassStranger:
		return fmt.Errorf("class %d is neither contact (1) nor stranger (2)", b.Class)
	case b.CapExp == 0:
		return errors.New("cap_exp is 0")
	case len(b.Holder) != ed25519.PublicKeySize:
		return fmt.Errorf("holder is %d bytes, want %d", len(b.Holder), ed25519.PublicKeySize)
	}
	return nil
}

// SignCap is the issuer's side of L6: it checks body (checkIssue), encodes it
// and signs the encoding with mbox, the private half of the Mbox in the
// issuer's current key set. An empty body.Type is taken as CapType; body is
// not modified. A body or key it cannot sign is invalid-input.
//
// The capability is only as current as mbox: a verifier accepts it while the
// owner's published mbox has the epoch written in body (SSR-W11).
func SignCap(mbox ed25519.PrivateKey, body *CapBody) (*Cap, error) {
	if body == nil {
		return nil, fail(ReasonInvalidInput, "nil cap body")
	}
	if len(mbox) != ed25519.PrivateKeySize {
		return nil, fail(ReasonInvalidInput, "mailbox key is %d bytes, want %d", len(mbox), ed25519.PrivateKeySize)
	}
	b := *body
	if b.Type == "" {
		b.Type = CapType
	}
	if err := b.checkIssue(); err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "cap body")
	}
	enc, err := b.Marshal()
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "encode cap body")
	}
	return &Cap{Body: enc, Sig: ed25519.Sign(mbox, enc)}, nil
}

// accessInput is the proof-of-possession input of L5:
// "anet-access/v2" || 0x00 || cap_id (16) || env_digest (32).
func accessInput(capID []byte, envDigest [32]byte) []byte {
	in := make([]byte, 0, len(accessLabel)+CapIDLen+len(envDigest))
	in = append(in, accessLabel...)
	in = append(in, capID...)
	return append(in, envDigest[:]...)
}

// SignAccess returns the holder's proof of possession for one envelope (core
// §3.2 L5): Ed25519(holder, "anet-access/v2" || 0x00 || cap_id || env_digest).
// envDigest is EnvDigest of the envelope it goes on, so the proof, and with it
// the access, cannot be moved to another envelope (SSR-W1). A sender signs a
// new proof on every attempt and only then calls SetAccess (ENG-I2).
//
// It returns nil when holder is not an Ed25519 private key or capID is not
// CapIDLen bytes; SetAccess refuses an access with that proof.
func SignAccess(holder ed25519.PrivateKey, capID []byte, envDigest [32]byte) []byte {
	if len(holder) != ed25519.PrivateKeySize || len(capID) != CapIDLen {
		return nil
	}
	return ed25519.Sign(holder, accessInput(capID, envDigest))
}

// capExpInWindow reports whether cap_exp is in the verification window of
// core §2.1 at now.
func capExpInWindow(capExp, now uint64) bool {
	lo := uint64(0)
	if now > CapExpGraceMS {
		lo = now - CapExpGraceMS
	}
	return lo <= capExp && capExp <= satAdd(now, CapExpMaxAheadMS)
}

// VerifyAccess checks a kind-1 delivery credential (outer key 7) for the
// envelope whose EnvDigest is envDigest. mbox is the owner's current mailbox
// key (from its published key set), owner the outer to of the envelope (the
// recipient the hub or the daemon routes it to), now unix ms. The steps run
// in the fixed order of SSR-W23 (CORE-K2), and the first that fails is
// reported; every failure is access-invalid, with the step's name as Detail:
//
//	decode  Cap.body is not a strict CoreDet CapBody (decodeCapBody), or its
//	        class is neither contact nor stranger
//	type    its type tag is not CapType
//	owner   its owner is not owner (a capability delivers only to its issuer)
//	epoch   its epoch is not mbox.epoch (a new mailbox key voids every
//	        capability the old one signed, SSR-W11)
//	sig     Cap.sig does not verify under mbox.pub
//	exp     cap_exp is outside [now - CapExpGraceMS, now + CapExpMaxAheadMS]
//	proof   the proof does not verify under CapBody.holder over (cap_id,
//	        envDigest): wrong holder key, or the access was made for another
//	        envelope
//
// An access that is not a well-formed kind-1 access (nil, kind 0, no cap, a
// sig or proof that is not SigLen bytes) fails before the first step, with
// Detail "parse", the step ParseOuter reports it under. The class check is in
// decode because the class decides which bucket a hub charges: a value with
// no bucket is not a capability (an interpretation of SSR-W23, which does
// not list it).
func VerifyAccess(a *Access, envDigest [32]byte, mbox Mbox, owner string, now uint64) error {
	bad := func(step, format string, args ...any) error {
		return &Error{Reason: ReasonAccessInvalid, Detail: step, Err: fmt.Errorf(format, args...)}
	}
	switch {
	case a == nil:
		return bad("parse", "no access")
	case a.Kind != AccessKindCap:
		return bad("parse", "access kind %d is not a capability (1)", a.Kind)
	case a.Cap == nil || len(a.Cap.Sig) != SigLen || len(a.Proof) != SigLen:
		return bad("parse", "a kind-1 access needs a capability with a %d-byte sig and a %d-byte proof", SigLen, SigLen)
	}
	body, err := decodeCapBody(a.Cap.Body)
	if err != nil {
		return failWrap(ReasonAccessInvalid, err, "decode")
	}
	if body.Class != CapClassContact && body.Class != CapClassStranger {
		return bad("decode", "class %d is neither contact (1) nor stranger (2)", body.Class)
	}
	if body.Type != CapType {
		return bad("type", "type %q, want %q", body.Type, CapType)
	}
	if owner == "" || body.Owner != owner {
		return bad("owner", "issued by %s, the envelope is for %s", body.Owner, owner)
	}
	if mbox.Epoch == 0 || body.Epoch != mbox.Epoch {
		return bad("epoch", "signed at mailbox epoch %d, the owner's is %d", body.Epoch, mbox.Epoch)
	}
	if len(mbox.Pub) != ed25519.PublicKeySize || !ed25519.Verify(mbox.Pub, a.Cap.Body, a.Cap.Sig) {
		return bad("sig", "the signature is not by the owner's mailbox key")
	}
	if !capExpInWindow(body.CapExp, now) {
		return bad("exp", "cap_exp %d is outside [now - %d, now + %d] at %d", body.CapExp, CapExpGraceMS, CapExpMaxAheadMS, now)
	}
	if !ed25519.Verify(body.Holder, accessInput(body.CapID, envDigest), a.Proof) {
		return bad("proof", "the proof is not by the holder key over this envelope")
	}
	return nil
}
