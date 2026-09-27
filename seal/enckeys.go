package seal

import (
	"bytes"
	"crypto/hpke"
	"errors"
	"math"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// EncKeySetType is the value of EncKeySet key 0 (§3.1). The type string is
// the version of the object: EncKeySet decoding rejects unknown fields, so a
// new field requires a new type string.
const EncKeySetType = "anet.enckeys/1"

// EncKey is one published encryption public key (§3.1).
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

// Retained reports whether a key ring following this package's policy still
// holds the private half at now: until NotAfter + KeyRetentionMS. A key ring
// uses it to decide whether a kid lookup succeeds (§3.6 step 2 "valid or
// inside the retention period").
func (k *EncKey) Retained(now uint64) bool {
	if k.NotAfter > math.MaxUint64-KeyRetentionMS {
		return true
	}
	return now < k.NotAfter+KeyRetentionMS
}

// check applies the per-key rules of §3.1 rule 3 that do not depend on the
// current time.
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
		return errors.New("validity exceeds 30 days")
	}
	return nil
}

// EncKeySet is the signed list of an AID's current encryption keys (§3.1).
type EncKeySet struct {
	Type     string   `cbor:"0,keyasint"` // EncKeySetType
	AID      string   `cbor:"1,keyasint"`
	Seq      uint64   `cbor:"2,keyasint"` // NextSeq(now, last); consumers keep a high-water mark on it
	Keys     []EncKey `cbor:"3,keyasint"` // 1..MaxKeysPerSet, ascending by NotBefore
	IssuedAt uint64   `cbor:"4,keyasint"` // unix ms
}

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

// checkStructure applies §3.1 rule 3 except the "valid now" clause.
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
	return nil
}

// checkValidAt applies the last clause of §3.1 rule 3: at least one key with
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

// decodeEncKeySet decodes set bytes and requires them to be the CoreDet
// encoding of the decoded value. The check rejects unknown fields and
// non-canonical encodings. Without it, two different byte strings could
// decode to the same set, and the high-water rule, which compares bytes at
// equal seq, would report a fork for what is one object.
func decodeEncKeySet(b []byte) (*EncKeySet, error) {
	var s EncKeySet
	if err := coredet.Unmarshal(b, &s); err != nil {
		return nil, failWrap(ReasonBadKeySet, err, "decode")
	}
	re, err := coredet.Marshal(s)
	if err != nil {
		return nil, failWrap(ReasonBadKeySet, err, "re-encode")
	}
	if !bytes.Equal(re, b) {
		return nil, fail(ReasonBadKeySet, "not the canonical encoding of an %s (unknown field or non-deterministic encoding)", EncKeySetType)
	}
	return &s, nil
}

// SignedEncKeySet is an EncKeySet with its detached signature (§3.1).
type SignedEncKeySet struct {
	Set         []byte `cbor:"1,keyasint"` // coredet(EncKeySet), the signed bytes
	KeyStateSeq uint64 `cbor:"2,keyasint"` // signer key_state_seq
	Sig         []byte `cbor:"3,keyasint"` // Ed25519 over Set, SigLen bytes
}

// Marshal returns the CoreDet encoding of s, the form carried in inner key
// 12 and served by the hub.
func (s *SignedEncKeySet) Marshal() ([]byte, error) { return coredet.Marshal(*s) }

// UnmarshalSignedEncKeySet decodes a SignedEncKeySet. It checks structure
// only; VerifyEncKeySet checks the content.
func UnmarshalSignedEncKeySet(b []byte) (*SignedEncKeySet, error) {
	var s SignedEncKeySet
	if err := coredet.Unmarshal(b, &s); err != nil {
		return nil, failWrap(ReasonBadKeySet, err, "decode signed key set")
	}
	return &s, nil
}

// SignFunc signs a preimage with the caller's current identity key and
// returns the key_state_seq it signed under. (*identity.Controller).Sign has
// this signature.
type SignFunc func(preimage []byte) (sig []byte, keyStateSeq uint64)

// SignEncKeySet encodes set and signs the encoding. It refuses a set that
// fails the time-independent rules of §3.1 rule 3, so a publisher cannot
// sign something every consumer will reject.
func SignEncKeySet(set *EncKeySet, sign SignFunc) (*SignedEncKeySet, error) {
	if set == nil || sign == nil {
		return nil, fail(ReasonInvalidInput, "nil set or signer")
	}
	if err := set.checkStructure(); err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "key set")
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
//  3. The set is well-formed: type, 1..4 keys, kid matches suite and
//     public key, validity windows, ascending not_before, and at least one
//     key with not_before <= now + ClockSkewMS < not_after.
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
// Key has no error result. Open reports every miss as
// ReasonUnknownKey, which §3.6 classifies as permanent: the message is
// acked and dropped. An implementation must therefore answer from memory
// (the key ring file of §3.1 is loaded at start and written through on each
// change) and must not map a storage read failure onto a miss; a storage
// failure is a temporary condition under §3.6 and is handled before Open is
// called.
type KeyRing interface {
	// Key returns the key pair whose kid equals kid, if the ring holds its
	// private half. A ring that follows this package's policy answers for
	// keys that are valid or inside their retention period (EncKey.Retained)
	// and for no others.
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
