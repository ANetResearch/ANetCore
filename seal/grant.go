package seal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"

	"github.com/ANetResearch/ANetCore/coredet"
)

// Grant is inner key 14 (core §2.3): a capability the sender of a message
// issues to its recipient, with the seed of the capability's holder key, so
// the recipient can later deliver to the sender under it (Access kind 1)
// without naming itself to the hub. It travels only inside the end-to-end
// ciphertext.
//
// The optional keys are pointers so that "absent" stays apart from an empty
// or false value: a key's presence is what the placement rules of CheckGrant
// judge.
//
//anet:wire Grant
type Grant struct {
	Cap        Cap    `cbor:"1,keyasint"` // the capability, as outer key 7 carries it
	HolderSeed []byte `cbor:"2,keyasint"` // ed25519.SeedSize bytes: the holder key's private seed
	Home       string `cbor:"3,keyasint"` // AID of the issuer's hub: a routing hint, not a URL
	// IX present makes a one-shot capability: it delivers only messages of
	// this interaction (equal to the inner ix of the message that carried it).
	IX *string `cbor:"4,keyasint,omitempty"`
	// P2P is the issuer's direct address host:port; only in a contact peer
	// capability (class contact, no ix). The daemon's dial filter judges the
	// address.
	P2P *string `cbor:"5,keyasint,omitempty"`
	// Pay true says the issuer prices some capability; only in a peer
	// capability (no ix).
	Pay *bool `cbor:"6,keyasint,omitempty"`
}

// HolderKey returns the holder's Ed25519 private key, the key SignAccess
// takes, or nil when HolderSeed is not ed25519.SeedSize bytes.
func (g *Grant) HolderKey() ed25519.PrivateKey {
	if g == nil || len(g.HolderSeed) != ed25519.SeedSize {
		return nil
	}
	return ed25519.NewKeyFromSeed(g.HolderSeed)
}

// rawBool decodes a CBOR true or false (major type 7, simple values 21 and
// 20). The generic decoder would also take null.
func rawBool(m fieldMap, k uint64) (bool, error) {
	raw, ok := m[k]
	if !ok {
		return false, fmt.Errorf("field %d missing", k)
	}
	switch {
	case len(raw) == 1 && raw[0] == 0xf5:
		return true, nil
	case len(raw) == 1 && raw[0] == 0xf4:
		return false, nil
	}
	return false, fmt.Errorf("field %d is not a boolean", k)
}

// decodeGrant is the strict decode of a Grant (step 1 of SSR-W7): a map with
// no key but 1-6 (no extension range, CORE-E3); key 1 a well-formed Cap
// (decodeCap); key 2 an ed25519.SeedSize-byte string; key 3 an AID (text, not
// empty, no U+0000: it becomes the X-ANet-Home header, CORE-E9); keys 4 and 5
// text and key 6 a boolean when present. Cap.Body is decoded by
// decodeCapBody, a step of its own.
func decodeGrant(raw []byte) (*Grant, error) {
	m, err := decodeFields(raw)
	if err != nil {
		return nil, fmt.Errorf("grant: %w", err)
	}
	if k, ok := firstKeyOutside(m, 1, 6); ok {
		return nil, fmt.Errorf("grant has key %d", k)
	}
	var g Grant
	capRaw, ok := m[1]
	if !ok {
		return nil, errors.New("grant: field 1 (cap) missing")
	}
	c, err := decodeCap(capRaw)
	if err != nil {
		return nil, fmt.Errorf("grant: %w", err)
	}
	g.Cap = *c
	if g.HolderSeed, err = rawBytes(m, 2); err != nil {
		return nil, fmt.Errorf("grant holder_seed: %w", err)
	}
	if len(g.HolderSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("grant holder_seed is %d bytes, want %d", len(g.HolderSeed), ed25519.SeedSize)
	}
	if g.Home, err = rawText(m, 3); err != nil {
		return nil, fmt.Errorf("grant home: %w", err)
	}
	if g.Home == "" || strings.IndexByte(g.Home, 0) >= 0 {
		return nil, errors.New("grant home must be an AID: not empty, no U+0000")
	}
	optText := func(k uint64, name string) (*string, error) {
		if _, ok := m[k]; !ok {
			return nil, nil
		}
		v, err := rawText(m, k)
		if err != nil {
			return nil, fmt.Errorf("grant %s: %w", name, err)
		}
		return &v, nil
	}
	if g.IX, err = optText(4, "ix"); err != nil {
		return nil, err
	}
	if g.P2P, err = optText(5, "p2p"); err != nil {
		return nil, err
	}
	if _, ok := m[6]; ok {
		v, err := rawBool(m, 6)
		if err != nil {
			return nil, fmt.Errorf("grant pay: %w", err)
		}
		g.Pay = &v
	}
	return &g, nil
}

// UnmarshalGrant decodes a Grant strictly (step 1 of CheckGrant): a failure
// is access-invalid with Detail "decode". It does not check the capability.
func UnmarshalGrant(b []byte) (*Grant, error) {
	g, err := decodeGrant(b)
	if err != nil {
		return nil, failWrap(ReasonAccessInvalid, err, "decode")
	}
	return g, nil
}

// Marshal returns the CoreDet encoding of g, the value of inner key 14. It
// refuses (invalid-input) a grant its recipient would ignore whatever the
// message: one that does not decode, whose Cap.Body is not a well-formed
// CapBody (checkIssue), whose holder seed is not the key of the capability's
// holder, or whose p2p or pay is where SSR-W7 rule 8 does not allow it. What
// depends on the message and the key set (owner, epoch, signature, ix, expiry)
// is CheckGrant's.
func (g *Grant) Marshal() ([]byte, error) {
	if g == nil {
		return nil, fail(ReasonInvalidInput, "nil grant")
	}
	b, err := coredet.Marshal(*g)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "encode grant")
	}
	d, err := decodeGrant(b)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "grant")
	}
	body, err := decodeCapBody(d.Cap.Body)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "grant cap")
	}
	if err := body.checkIssue(); err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "grant cap body")
	}
	if !bytes.Equal(d.HolderKey().Public().(ed25519.PublicKey), body.Holder) {
		return nil, fail(ReasonInvalidInput, "grant holder_seed is not the key of the capability's holder")
	}
	if err := grantPlacement(d, body); err != nil {
		return nil, failWrap(ReasonInvalidInput, err.err, "grant %s", err.step)
	}
	return b, nil
}

// stepError is a failed step of CheckGrant before it becomes an *Error.
type stepError struct {
	step string
	err  error
}

// grantPlacement is rule 8 of SSR-W7: key 5 (p2p) only in a contact
// capability without key 4, key 6 (pay) only without key 4.
func grantPlacement(g *Grant, body *CapBody) *stepError {
	if g.P2P != nil && (body.Class != CapClassContact || g.IX != nil) {
		return &stepError{"p2p", errors.New("p2p is only for a contact peer capability (class contact, no ix)")}
	}
	if g.Pay != nil && g.IX != nil {
		return &stepError{"pay", errors.New("pay is only for a peer capability (no ix)")}
	}
	return nil
}

// CheckGrant checks inner key 14 of an opened message whose signature and
// attached key set the receiver has verified (receive steps 7 and 8). keys is
// that key set, the one VerifyInnerKeys returned for the same message; now is
// the arrival time, unix ms. It returns the grant and its decoded capability
// body when the recipient may keep the grant (in caps_held, with the message
// it came in, SSR-W8), and otherwise an error.
//
// The checks run in the order of SSR-W7 and the first that fails is reported:
// access-invalid, with the step's name as Detail:
//
//	decode  the grant does not decode strictly (decodeGrant)
//	body    Cap.body is not a strict CoreDet CapBody (decodeCapBody)
//	type    its type tag is not CapType
//	owner   its owner is not inner.From: a grant hands over the sender's own
//	        capability, never someone else's
//	keys    keys is nil or is not inner.From's key set
//	epoch   its epoch is not keys.mbox.epoch
//	sig     Cap.sig does not verify under keys.mbox.pub
//	holder  the holder seed is not the key of CapBody.holder
//	class   the class is neither contact nor stranger
//	exp     cap_exp is outside [now - CapExpGraceMS, now + CapExpMaxAheadMS]
//	ix      key 4 is present and is not inner.IX
//	p2p     key 5 is present in a stranger capability or with key 4
//	pay     key 6 is present with key 4
//
// A failure is never a reason to refuse the message: the receiver ignores the
// grant, counts grant-invalid and goes on (CORE-K4). A message without key 14
// has no grant to check; CheckGrant fails it at decode. A nil inner is
// invalid-input.
func CheckGrant(inner *SealedInner, keys *EncKeySet, now uint64) (*Grant, *CapBody, error) {
	if inner == nil {
		return nil, nil, fail(ReasonInvalidInput, "nil inner")
	}
	bad := func(step string, err error) (*Grant, *CapBody, error) {
		return nil, nil, &Error{Reason: ReasonAccessInvalid, Detail: step, Err: err}
	}
	// 1. The grant.
	g, err := decodeGrant(inner.Grant)
	if err != nil {
		return bad("decode", err)
	}
	// 2. The capability body and its type.
	body, err := decodeCapBody(g.Cap.Body)
	if err != nil {
		return bad("body", err)
	}
	if body.Type != CapType {
		return bad("type", fmt.Errorf("type %q, want %q", body.Type, CapType))
	}
	// 3. Issued by the sender.
	if body.Owner != inner.From {
		return bad("owner", fmt.Errorf("issued by %s, the message is from %s", body.Owner, inner.From))
	}
	// 4. Signed by the sender's current mailbox key.
	if keys == nil || keys.AID != inner.From {
		return bad("keys", errors.New("no verified key set of the sender to check the capability against"))
	}
	if keys.Mbox.Epoch == 0 || body.Epoch != keys.Mbox.Epoch {
		return bad("epoch", fmt.Errorf("signed at mailbox epoch %d, the sender's key set has %d", body.Epoch, keys.Mbox.Epoch))
	}
	if len(keys.Mbox.Pub) != ed25519.PublicKeySize || !ed25519.Verify(keys.Mbox.Pub, g.Cap.Body, g.Cap.Sig) {
		return bad("sig", errors.New("the signature is not by the sender's mailbox key"))
	}
	// 5. The seed is the holder's.
	if !bytes.Equal(g.HolderKey().Public().(ed25519.PublicKey), body.Holder) {
		return bad("holder", errors.New("the holder seed is not the key of the capability's holder"))
	}
	// 6. Class and expiry.
	if body.Class != CapClassContact && body.Class != CapClassStranger {
		return bad("class", fmt.Errorf("class %d is neither contact (1) nor stranger (2)", body.Class))
	}
	if !capExpInWindow(body.CapExp, now) {
		return bad("exp", fmt.Errorf("cap_exp %d is outside [now - %d, now + %d] at %d", body.CapExp, CapExpGraceMS, CapExpMaxAheadMS, now))
	}
	// 7. A one-shot capability is for this interaction.
	if g.IX != nil && *g.IX != inner.IX {
		return bad("ix", fmt.Errorf("one-shot for interaction %q, the message is in %q", *g.IX, inner.IX))
	}
	// 8. Where p2p and pay may appear.
	if se := grantPlacement(g, body); se != nil {
		return bad(se.step, se.err)
	}
	return g, body, nil
}
