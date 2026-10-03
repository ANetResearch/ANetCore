package seal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"errors"
	"fmt"
	"math"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// EncKeySetType is the value of EncKeySet key 0. The type string is the
// version of the object: an EncKeySet has no extension keys and decoding
// refuses every key it does not name, so a new field requires a new type
// string.
const EncKeySetType = "anet.enckeys/2"

// EncKey is one published encryption public key: an epoch key, valid for one
// epoch.
//
//anet:wire EncKey
type EncKey struct {
	KID       []byte `cbor:"1,keyasint"` // KID(Suite, Pub)
	Suite     Suite  `cbor:"2,keyasint"`
	Pub       []byte `cbor:"3,keyasint"` // 32 bytes for suite 1
	NotBefore uint64 `cbor:"4,keyasint"` // unix ms
	NotAfter  uint64 `cbor:"5,keyasint"` // unix ms, exclusive; NotAfter - NotBefore <= MaxKeyValidityMS
}

// NewEncKey returns the EncKey record for pub with its kid filled in.
func NewEncKey(suite Suite, pub []byte, notBefore, notAfter uint64) EncKey {
	return EncKey{
		KID:       KID(suite, pub),
		Suite:     suite,
		Pub:       append([]byte(nil), pub...),
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
}

// ValidAt reports whether now is inside [NotBefore, NotAfter).
func (k *EncKey) ValidAt(now uint64) bool { return k.NotBefore <= now && now < k.NotAfter }

// check applies the rules for one key that do not depend on the current
// time: a suite, a 16-byte kid equal to KID(suite, pub), a public key of the
// suite's length, and a validity window of at most MaxKeyValidityMS.
func (k *EncKey) check() error {
	if k.Suite == 0 {
		return errors.New("suite 0 is not assigned")
	}
	if len(k.KID) != KIDLen {
		return errors.New("kid is not 16 bytes")
	}
	if p := params(k.Suite); p != nil {
		if len(k.Pub) != p.pubLen {
			return errors.New("public key has the wrong length for its suite")
		}
	} else if len(k.Pub) == 0 {
		return errors.New("public key is empty")
	}
	if !bytes.Equal(k.KID, KID(k.Suite, k.Pub)) {
		return errors.New("kid does not match suite and public key")
	}
	if k.NotAfter <= k.NotBefore {
		return errors.New("not_after is not after not_before")
	}
	if k.NotAfter-k.NotBefore > MaxKeyValidityMS {
		return fmt.Errorf("validity of %d ms exceeds %d days", k.NotAfter-k.NotBefore, MaxKeyValidityMS/dayMS)
	}
	return nil
}

// Mbox is the mailbox signing key in a key set: the Ed25519 key that signs
// the delivery capabilities its owner issues, and its epoch. A planned
// rotation of the identity re-signs the set with the same Mbox; an emergency
// rotation replaces the key and raises the epoch by one, which invalidates
// every capability the old key signed.
//
//anet:wire Mbox
type Mbox struct {
	Epoch uint64 `cbor:"1,keyasint"` // >= 1
	Pub   []byte `cbor:"2,keyasint"` // Ed25519 public key, 32 bytes
}

// EncKeySet is the signed list of an AID's epoch keys and its mailbox
// signing key.
//
//anet:wire EncKeySet
type EncKeySet struct {
	Type     string   `cbor:"0,keyasint"` // EncKeySetType
	AID      string   `cbor:"1,keyasint"`
	Seq      uint64   `cbor:"2,keyasint"` // NextSeq(now, last); consumers keep a high-water mark on it
	Keys     []EncKey `cbor:"3,keyasint"` // 1..MaxKeysPerSet, ascending by NotBefore
	IssuedAt uint64   `cbor:"4,keyasint"` // unix ms
	Mbox     Mbox     `cbor:"5,keyasint"` // the owner's mailbox signing key
}

// encKeySetKeys are the keys of an EncKeySet, all required, by number.
var encKeySetKeys = [...]string{0: "t", 1: "aid", 2: "seq", 3: "keys", 4: "issued_at", 5: "mbox"}

// Marshal returns the CoreDet encoding of s: the bytes that are signed and
// carried as SignedEncKeySet.Set.
func (s *EncKeySet) Marshal() ([]byte, error) { return coredet.Marshal(*s) }

// NextSeq returns max(now, lastSeq+1), the seq a publisher assigns to its
// next key set (§3.1). Using the clock keeps the value meaningful after a
// lost state file; the +1 keeps it strictly increasing when the clock does
// not move or moves back.
func NextSeq(now, lastSeq uint64) uint64 {
	if lastSeq == math.MaxUint64 {
		return lastSeq
	}
	return max(now, lastSeq+1)
}

// checkStructure applies the rules of a key set that do not depend on the
// current time. With checkValidAt and the decoding rules of decodeEncKeySet
// they are the five classes a signer and a verifier refuse, each with
// ReasonBadKeySet:
//
//  1. the type is not EncKeySetType, or the encoding holds a key the format
//     does not name (decodeEncKeySet);
//  2. no keys, more than MaxKeysPerSet, or a key valid for longer than
//     MaxKeyValidityMS;
//  3. a repeated kid, a kid that is not KID(suite, pub), or not_before out
//     of ascending order;
//  4. no mailbox signing key, its epoch 0, or its public key not 32 bytes;
//  5. no key valid at now + ClockSkewMS (checkValidAt).
//
// Epochs need not be aligned on the UTC day for a set to verify: aligning
// them is the publisher's duty, and a verifier that enforced it would turn a
// publisher's clock error into undeliverable mail.
func (s *EncKeySet) checkStructure() error {
	if s.Type != EncKeySetType {
		return fail(ReasonBadKeySet, "type %q, want %q", s.Type, EncKeySetType)
	}
	if s.AID == "" {
		return fail(ReasonBadKeySet, "empty aid")
	}
	if len(s.Keys) == 0 || len(s.Keys) > MaxKeysPerSet {
		return fail(ReasonBadKeySet, "%d keys, want 1..%d", len(s.Keys), MaxKeysPerSet)
	}
	seen := make(map[string]bool, len(s.Keys))
	for i := range s.Keys {
		k := &s.Keys[i]
		if err := k.check(); err != nil {
			return failWrap(ReasonBadKeySet, err, "key %d", i)
		}
		if seen[string(k.KID)] {
			return fail(ReasonBadKeySet, "key %d repeats a kid", i)
		}
		seen[string(k.KID)] = true
		if i > 0 && k.NotBefore < s.Keys[i-1].NotBefore {
			return fail(ReasonBadKeySet, "keys not in ascending not_before order at %d", i)
		}
	}
	if s.Mbox.Epoch == 0 {
		return fail(ReasonBadKeySet, "mbox epoch is 0, want 1 or more")
	}
	if len(s.Mbox.Pub) != ed25519.PublicKeySize {
		return fail(ReasonBadKeySet, "mbox pub is %d bytes, want %d", len(s.Mbox.Pub), ed25519.PublicKeySize)
	}
	return nil
}

// checkValidAt applies the time rule of a key set: at least one key with
// not_before <= now + ClockSkewMS < not_after.
func (s *EncKeySet) checkValidAt(now uint64) error {
	t := satAdd(now, ClockSkewMS)
	for i := range s.Keys {
		if s.Keys[i].NotBefore <= t && t < s.Keys[i].NotAfter {
			return nil
		}
	}
	return fail(ReasonBadKeySet, "no key valid at now + clock skew")
}

// decodeEncKeySet decodes set bytes. It requires every key of the format and
// no other (the type has no extension range), decodes strictly, and requires
// the bytes to be the CoreDet encoding of the decoded value. The last check
// rejects non-canonical encodings: without it two different byte strings
// could decode to the same set, and the high-water rule, which compares bytes
// at equal seq, would report a fork for what is one object.
func decodeEncKeySet(b []byte) (*EncKeySet, error) {
	m, err := decodeFields(b)
	if err != nil {
		return nil, failWrap(ReasonBadKeySet, err, "decode")
	}
	// The type first: a set of another version should say so, not that it
	// lacks a key this version has.
	if t, ok := m[0]; ok {
		var typ string
		if err := coredet.Unmarshal(t, &typ); err != nil || typ != EncKeySetType {
			return nil, fail(ReasonBadKeySet, "type %q, want %q", typ, EncKeySetType)
		}
	}
	if k, ok := firstUnknownKey(m, uint64(len(encKeySetKeys))); ok {
		return nil, fail(ReasonBadKeySet, "key %d is not a key of %s", k, EncKeySetType)
	}
	for n, name := range encKeySetKeys {
		if _, ok := m[uint64(n)]; !ok {
			return nil, fail(ReasonBadKeySet, "key %d (%s) is missing", n, name)
		}
	}
	var s EncKeySet
	if err := coredet.UnmarshalStrict(b, &s); err != nil {
		return nil, failWrap(ReasonBadKeySet, err, "decode")
	}
	re, err := coredet.Marshal(s)
	if err != nil {
		return nil, failWrap(ReasonBadKeySet, err, "re-encode")
	}
	if !bytes.Equal(re, b) {
		return nil, fail(ReasonBadKeySet, "not the canonical encoding of an %s (a key of an EncKey or the mbox is missing, or an encoding is not deterministic)", EncKeySetType)
	}
	return &s, nil
}

// firstUnknownKey returns the smallest key of m at or above n, if there is
// one: in an object whose keys are 0..n-1, the first one it does not name.
func firstUnknownKey(m fieldMap, n uint64) (uint64, bool) {
	found := false
	var least uint64
	for k := range m {
		if k >= n && (!found || k < least) {
			least, found = k, true
		}
	}
	return least, found
}

// SignedEncKeySet is an EncKeySet with its owner's signature over the set's
// encoding, made with the identity key at the head of the owner's KEL.
//
//anet:wire SignedEncKeySet
type SignedEncKeySet struct {
	Set         []byte `cbor:"1,keyasint"` // coredet(EncKeySet), the signed bytes
	KeyStateSeq uint64 `cbor:"2,keyasint"` // signer key_state_seq
	Sig         []byte `cbor:"3,keyasint"` // Ed25519 over Set, SigLen bytes
}

// Marshal returns the CoreDet encoding of s, the form carried in inner key
// 12 and served by the hub.
func (s *SignedEncKeySet) Marshal() ([]byte, error) { return coredet.Marshal(*s) }

// UnmarshalSignedEncKeySet decodes a SignedEncKeySet: all three keys and no
// other. It checks structure only; VerifyEncKeySet checks the content.
func UnmarshalSignedEncKeySet(b []byte) (*SignedEncKeySet, error) {
	m, err := decodeFields(b)
	if err != nil {
		return nil, failWrap(ReasonBadKeySet, err, "decode signed key set")
	}
	for n, name := range [...]string{1: "set", 2: "key_state_seq", 3: "sig"} {
		if _, ok := m[uint64(n)]; n > 0 && !ok {
			return nil, fail(ReasonBadKeySet, "signed key set: key %d (%s) is missing", n, name)
		}
	}
	var s SignedEncKeySet
	if err := coredet.UnmarshalStrict(b, &s); err != nil {
		return nil, failWrap(ReasonBadKeySet, err, "decode signed key set")
	}
	return &s, nil
}

// SignFunc signs a preimage with the caller's current identity key and
// returns the key_state_seq it signed under. (*identity.Controller).Sign has
// this signature.
type SignFunc func(preimage []byte) (sig []byte, keyStateSeq uint64)

// SignEncKeySet encodes set and signs the encoding. It refuses, with
// ReasonBadKeySet, every set VerifyEncKeySet refuses for its content, so a
// publisher cannot sign something every consumer rejects; the time rule is
// judged at set.IssuedAt, the moment the set says it was made. A nil set or
// signer, or a signer that misbehaves, is ReasonInvalidInput.
func SignEncKeySet(set *EncKeySet, sign SignFunc) (*SignedEncKeySet, error) {
	if set == nil || sign == nil {
		return nil, fail(ReasonInvalidInput, "nil set or signer")
	}
	if err := set.checkStructure(); err != nil {
		return nil, err
	}
	if err := set.checkValidAt(set.IssuedAt); err != nil {
		return nil, err
	}
	b, err := set.Marshal()
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "encode key set")
	}
	sig, seq := sign(b)
	if len(sig) != SigLen {
		return nil, fail(ReasonInvalidInput, "signer returned %d signature bytes, want %d", len(sig), SigLen)
	}
	return &SignedEncKeySet{Set: b, KeyStateSeq: seq, Sig: sig}, nil
}

// VerifyEncKeySet verifies a signed key set against the owner's KEL and
// returns the decoded set (§3.1):
//
//  1. kel replays, and the AID it replays to, set.aid and expectAID are
//     all equal. expectAID is what the caller already believes: the
//     recipient AID when sending, inner.from when receiving. Without it a
//     party that controls the transport (the hub) could return its own
//     valid KEL and key set for someone else's AID, and the sender would
//     seal to the hub's key.
//  2. The signature is by an active key state, that is by the key in force
//     at the KEL head, and the AID is not deactivated. A key set is a
//     present-tense statement ("these are my keys now"), so no rotation
//     grace applies: after a rotation the owner must re-sign. A key state
//     followed only by ixn or drt events is still active; those events do
//     not change the signing key.
//  3. The set is well-formed (checkStructure, checkValidAt): type, 1..32
//     keys, kid matches suite and public key, validity windows of at most
//     two days, ascending not_before, a mailbox signing key, and at least
//     one key with not_before <= now + ClockSkewMS < not_after.
//
// The set bytes are decoded first, strictly (decodeEncKeySet), before the
// KEL is replayed.
//
// now is unix ms.
func VerifyEncKeySet(signed *SignedEncKeySet, expectAID string, kel []identity.SignedEvent, now uint64) (*EncKeySet, error) {
	if signed == nil {
		return nil, fail(ReasonBadKeySet, "nil signed key set")
	}
	set, err := decodeEncKeySet(signed.Set)
	if err != nil {
		return nil, err
	}
	// Rule 1.
	states, err := identity.Replay(kel)
	if err != nil {
		return nil, failWrap(ReasonBadKEL, err, "replay")
	}
	kelAID := states[len(states)-1].AID
	if kelAID != expectAID {
		return nil, fail(ReasonAIDMismatch, "KEL replays to %s, expected %s", kelAID, expectAID)
	}
	if set.AID != expectAID {
		return nil, fail(ReasonAIDMismatch, "key set names %s, expected %s", set.AID, expectAID)
	}
	// Rule 2.
	if len(signed.Sig) != SigLen {
		return nil, fail(ReasonBadSig, "signature is %d bytes, want %d", len(signed.Sig), SigLen)
	}
	if signed.KeyStateSeq >= uint64(len(states)) {
		return nil, fail(ReasonBadKeyState, "key_state_seq %d beyond KEL of %d events", signed.KeyStateSeq, len(states))
	}
	if states[len(states)-1].Status == identity.StatusDeactivated {
		return nil, fail(ReasonRevokedKey, "AID is deactivated")
	}
	if ks := states[signed.KeyStateSeq]; ks.Status != identity.StatusActive {
		return nil, fail(ReasonBadKeyState, "signed at key_state_seq %d, whose key was retired at %d; a key set needs the current key", signed.KeyStateSeq, ks.SupersededAt)
	}
	if err := identity.VerifyObject(kel, expectAID, signed.KeyStateSeq, now, signed.Set, signed.Sig); err != nil {
		return nil, fromVErr(err)
	}
	// Rule 3.
	if err := set.checkStructure(); err != nil {
		return nil, err
	}
	if err := set.checkValidAt(now); err != nil {
		return nil, err
	}
	return set, nil
}

// SelectKey returns the key a sender seals to (§3.1 "sender key choice"):
// among keys of a suite this build implements with not_before <= now <
// not_after, the one with the largest not_before.
//
// When no key is valid at now but one becomes valid within ClockSkewMS, that
// key is returned. §3.1 rule 3 accepts such a set, so without the fallback a
// set that VerifyEncKeySet accepted could be unusable until the sender's
// clock catches up with the publisher's; the recipient decides by kid and
// holds the key regardless of the sender's clock.
func SelectKey(set *EncKeySet, now uint64) (*EncKey, error) {
	if set == nil {
		return nil, fail(ReasonNoUsableKey, "nil key set")
	}
	var best *EncKey
	for i := range set.Keys {
		k := &set.Keys[i]
		if !Supported(k.Suite) || !k.ValidAt(now) {
			continue
		}
		if best == nil || k.NotBefore >= best.NotBefore {
			best = k
		}
	}
	if best == nil {
		t := satAdd(now, ClockSkewMS)
		for i := range set.Keys {
			k := &set.Keys[i]
			if !Supported(k.Suite) || !(k.NotBefore <= t && t < k.NotAfter) {
				continue
			}
			if best == nil || k.NotBefore < best.NotBefore {
				best = k
			}
		}
	}
	if best == nil {
		return nil, fail(ReasonNoUsableKey, "no key of a supported suite is valid at %d", now)
	}
	out := NewEncKey(best.Suite, best.Pub, best.NotBefore, best.NotAfter)
	return &out, nil
}

// KeyPair is an EncKey with its private half, the unit a key ring stores.
// Private is the RFC 9180 SerializePrivateKey output and is secret.
//
//anet:wire KeyPair
type KeyPair struct {
	Public  EncKey `cbor:"1,keyasint"`
	Private []byte `cbor:"2,keyasint"`
}

// GenerateKeyPair creates a fresh key pair for suite, valid in
// [notBefore, notAfter).
func GenerateKeyPair(suite Suite, notBefore, notAfter uint64) (*KeyPair, error) {
	p := params(suite)
	if p == nil {
		return nil, fail(ReasonUnknownSuite, "suite %d", suite)
	}
	sk, err := p.kem.GenerateKey()
	if err != nil {
		return nil, failWrap(ReasonInternalError, err, "generate key")
	}
	return newKeyPair(suite, sk, notBefore, notAfter)
}

// DeriveKeyPair derives a key pair from ikm with RFC 9180 DeriveKeyPair. The
// result is a function of ikm alone, so ikm must be secret and carry at
// least 32 bytes of entropy. Its intended use is reproducible test and
// conformance keys; a daemon uses GenerateKeyPair.
func DeriveKeyPair(suite Suite, ikm []byte, notBefore, notAfter uint64) (*KeyPair, error) {
	p := params(suite)
	if p == nil {
		return nil, fail(ReasonUnknownSuite, "suite %d", suite)
	}
	sk, err := p.kem.DeriveKeyPair(ikm)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "derive key")
	}
	return newKeyPair(suite, sk, notBefore, notAfter)
}

func newKeyPair(suite Suite, sk hpke.PrivateKey, notBefore, notAfter uint64) (*KeyPair, error) {
	priv, err := sk.Bytes()
	if err != nil {
		return nil, failWrap(ReasonInternalError, err, "serialize private key")
	}
	kp := &KeyPair{Public: NewEncKey(suite, sk.PublicKey().Bytes(), notBefore, notAfter), Private: priv}
	if err := kp.Public.check(); err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "key validity")
	}
	return kp, nil
}

// KeyRing is the recipient's private key store as Open sees it.
//
// A ring answers for every private key it holds; when to delete one is the
// holder's decision, not this package's. Key has no error result. Open
// reports every miss as ReasonUnknownKey, which §3.6 classifies as permanent:
// the message is acked and dropped. An implementation must therefore answer
// from memory (the key ring file is loaded at start and written through on
// each change) and must not map a storage read failure onto a miss; a
// storage failure is a temporary condition under §3.6 and is handled before
// Open is called.
type KeyRing interface {
	// Key returns the key pair whose kid equals kid, if the ring holds its
	// private half.
	Key(kid []byte) (*KeyPair, bool)
}

// StaticKeyRing is a KeyRing over a fixed list. It applies no retention
// rule; it answers for every pair it holds.
type StaticKeyRing []*KeyPair

// Key implements KeyRing.
func (r StaticKeyRing) Key(kid []byte) (*KeyPair, bool) {
	for _, kp := range r {
		if kp != nil && bytes.Equal(kp.Public.KID, kid) {
			return kp, true
		}
	}
	return nil, false
}

// fromVErr maps an identity.VerifyObject failure onto a reason.
func fromVErr(err error) *Error {
	var ve *identity.VErr
	if errors.As(err, &ve) {
		switch ve.Reason {
		case "INVALID_SIGNATURE":
			return failWrap(ReasonBadSig, err, "")
		case "KEY_STATE_DOWNGRADE":
			return failWrap(ReasonBadKeyState, err, "")
		case "REVOKED_KEY":
			return failWrap(ReasonRevokedKey, err, "")
		}
	}
	return failWrap(ReasonBadKEL, err, "")
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}
