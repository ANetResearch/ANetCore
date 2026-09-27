package seal

import (
	"bytes"
	"crypto/hpke"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
)

// EnvelopeVersion is the only outer version this package reads and writes
// (§3.3 key 1). Adding a must-understand field to either map requires
// incrementing it.
const EnvelopeVersion = 1

// HPKELabel is the value of HPKE info key 1 (§3.3).
const HPKELabel = "anet-relay/v1"

// Inner message types (§3.4). The body of each is defined in the
// delegation package; this package carries the body as opaque bytes and
// does not restrict the type.
const (
	TypeDelegate = "anet.delegate/1" // DelegateReq, requester -> provider
	TypeMessage  = "anet.message/1"  // ChatMsg, both directions
	TypeStatus   = "anet.status/1"   // StatusMsg, provider -> requester
	TypeResult   = "anet.result/1"   // ResultResp, provider -> requester
)

// Outer envelope keys (§3.3).
const (
	outerKeyV     = 1
	outerKeyTo    = 2
	outerKeySuite = 3
	outerKeyKID   = 4
	outerKeyEnc   = 5
	outerKeyCT    = 6
	// Key 7 (access) is reserved for sealed-sender delivery tokens. It is
	// not in outerKnown: an envelope that carries it is rejected until a
	// version that defines it.
)

var outerKnown = map[uint64]bool{
	outerKeyV: true, outerKeyTo: true, outerKeySuite: true,
	outerKeyKID: true, outerKeyEnc: true, outerKeyCT: true,
}

// Inner message keys (§3.3).
const (
	keyFrom = 1
	keySeq  = 2
	keyTo   = 3
	keyType = 4
	keyIX   = 5
	keyMID  = 6
	keyTS   = 7
	keyExp  = 8
	keyBody = 9
	keyKEL  = 10
	keyKeys = 12
	keySig  = 20
	keyPad  = 21
)

var innerKnown = map[uint64]bool{
	keyFrom: true, keySeq: true, keyTo: true, keyType: true, keyIX: true,
	keyMID: true, keyTS: true, keyExp: true, keyBody: true, keyKEL: true,
	keyKeys: true, keySig: true, keyPad: true,
}

// SealedEnvelope is the outer object, the only part a hub sees (§3.3).
type SealedEnvelope struct {
	V     uint64 `cbor:"1,keyasint"` // EnvelopeVersion
	To    string `cbor:"2,keyasint"` // recipient AID
	Suite Suite  `cbor:"3,keyasint"`
	KID   []byte `cbor:"4,keyasint"` // KIDLen bytes, the recipient key sealed to
	Enc   []byte `cbor:"5,keyasint"` // HPKE encapsulated key
	CT    []byte `cbor:"6,keyasint"` // HPKE ciphertext of the inner encoding
}

// Marshal returns the CoreDet encoding of e.
func (e *SealedEnvelope) Marshal() ([]byte, error) { return coredet.Marshal(*e) }

// SealedInner is the plaintext inside the envelope (§3.3).
//
// The struct has no CBOR tags on purpose. The wire form is built by Seal as
// an integer-keyed field map, so that the signature preimage and the
// padding are computed over exactly the values that are sent, including
// extension keys. Encoding the struct directly would not produce a valid
// inner. The field numbers are given in the comments.
type SealedInner struct {
	From        string // 1: sender AID
	KeyStateSeq uint64 // 2: sender key_state_seq the signature was made under
	To          string // 3: recipient AID; must equal the outer to
	Type        string // 4: Type* constant
	IX          string // 5: interaction id
	MID         []byte // 6: message id, MIDLen bytes; the replay key with From
	TS          uint64 // 7: send time, unix ms
	Exp         uint64 // 8: expiry, unix ms; exp - ts <= MaxMessageLifetimeMS
	Body        []byte // 9: type-specific payload
	KEL         []byte // 10: sender KEL (identity.MarshalKEL), within MaxKELBytes / MaxKELEvents
	Keys        []byte // 12: sender SignedEncKeySet encoding
	Sig         []byte // 20: Ed25519 over the preimage; set by Seal
	Pad         []byte // 21: zero bytes; set by Seal, not signed

	// Ext holds fields with keys >= FirstIgnorableKey, each value the CBOR
	// encoding of the field. A receiver that does not understand them
	// ignores them, but they are inside the signature.
	Ext map[uint64][]byte
}

// NewMID returns a fresh random message id.
func NewMID() []byte {
	b := make([]byte, MIDLen)
	// crypto/rand.Read does not return an error since Go 1.24; on failure
	// of the system source it terminates the program.
	_, _ = rand.Read(b)
	return b
}

// HPKEInfo returns the HPKE info string for an envelope (§3.3):
// coredet({1: "anet-relay/v1", 2: to, 3: suite, 4: kid}). It binds the key
// schedule to the recipient AID and key, so a ciphertext cannot be moved to
// another envelope header without the AEAD failing.
func HPKEInfo(to string, suite Suite, kid []byte) ([]byte, error) {
	return coredet.Marshal(struct {
		Label string `cbor:"1,keyasint"`
		To    string `cbor:"2,keyasint"`
		Suite Suite  `cbor:"3,keyasint"`
		KID   []byte `cbor:"4,keyasint"`
	}{HPKELabel, to, suite, kid})
}

// ParseOuter decodes an envelope and applies the structural checks a hub
// makes before accepting it for relay (§3.7) and a daemon makes as §3.6 step
// 1: v == 1, a non-empty to, a suite this build implements, a 16-byte kid,
// an enc of the suite's length, and a non-empty ct. Keys 0-63 other than
// 1-6 are rejected; keys >= 64 are ignored. It does not compare to with any
// AID; the hub compares it with to_aid and Open with the local AID.
func ParseOuter(envelope []byte) (*SealedEnvelope, error) {
	fields, err := decodeFields(envelope)
	if err != nil {
		return nil, failWrap(ReasonBadOuter, err, "decode")
	}
	// The version is checked before the other fields: a later version may
	// define other keys, and the useful report for it is the version.
	v, err := rawUint(fields, outerKeyV)
	if err != nil {
		return nil, failWrap(ReasonBadOuter, err, "")
	}
	if v != EnvelopeVersion {
		return nil, fail(ReasonBadVersion, "v=%d, want %d", v, EnvelopeVersion)
	}
	if k, ok := firstUnknownCritical(fields, outerKnown); ok {
		return nil, fail(ReasonUnknownField, "outer key %d", k)
	}
	var e SealedEnvelope
	e.V = v
	if e.To, err = rawText(fields, outerKeyTo); err != nil {
		return nil, failWrap(ReasonBadOuter, err, "")
	}
	suite, err := rawUint(fields, outerKeySuite)
	if err != nil {
		return nil, failWrap(ReasonBadOuter, err, "")
	}
	if suite > 0xff || !Supported(Suite(suite)) {
		return nil, fail(ReasonUnknownSuite, "suite %d", suite)
	}
	e.Suite = Suite(suite)
	if e.KID, err = rawBytes(fields, outerKeyKID); err != nil {
		return nil, failWrap(ReasonBadOuter, err, "")
	}
	if e.Enc, err = rawBytes(fields, outerKeyEnc); err != nil {
		return nil, failWrap(ReasonBadOuter, err, "")
	}
	if e.CT, err = rawBytes(fields, outerKeyCT); err != nil {
		return nil, failWrap(ReasonBadOuter, err, "")
	}
	switch {
	case e.To == "":
		return nil, fail(ReasonBadOuter, "empty to")
	case len(e.KID) != KIDLen:
		return nil, fail(ReasonBadOuter, "kid is %d bytes, want %d", len(e.KID), KIDLen)
	case len(e.Enc) != params(e.Suite).encLen:
		return nil, fail(ReasonBadOuter, "enc is %d bytes, want %d", len(e.Enc), params(e.Suite).encLen)
	case len(e.CT) == 0:
		return nil, fail(ReasonBadOuter, "empty ct")
	}
	return &e, nil
}

// ParseKEL decodes a KEL carried in an inner message or served by a hub,
// enforcing MaxKELBytes before decoding and MaxKELEvents after. It does not
// replay the KEL.
func ParseKEL(b []byte) ([]identity.SignedEvent, error) {
	if len(b) > MaxKELBytes {
		return nil, fail(ReasonKELTooLarge, "%d bytes, cap %d", len(b), MaxKELBytes)
	}
	kel, err := identity.UnmarshalKEL(b)
	if err != nil {
		return nil, failWrap(ReasonBadKEL, err, "decode")
	}
	if len(kel) == 0 {
		return nil, fail(ReasonBadKEL, "empty KEL")
	}
	if len(kel) > MaxKELEvents {
		return nil, fail(ReasonKELTooLarge, "%d events, cap %d", len(kel), MaxKELEvents)
	}
	return kel, nil
}

// Seal signs inner and encrypts it to recipient, returning the envelope
// bytes (§3.5 step 2).
//
// The caller fills every field except Sig and Pad, which Seal sets (values
// present in the input are ignored). inner.KeyStateSeq must be the seq the
// signer will sign under (for an identity.Controller, CurrentSeq()); Seal
// checks it against what sign returns, because the seq is inside the signed
// preimage and a rotation between the two calls would otherwise produce a
// signature that no receiver accepts.
//
// The signature covers the HPKE enc, so Seal signs after the HPKE sender
// context exists. The result is randomized: sealing the same inner twice
// gives different bytes. A retry of one logical message resends the bytes
// from the first call (§3.3).
func Seal(inner *SealedInner, recipient *EncKey, sign SignFunc) ([]byte, error) {
	return seal(inner, recipient, sign, nil)
}

// seal is Seal with a hook that runs on the final field map, after signing
// and padding and before encryption. Tests use it to alter a signed field
// while keeping the HPKE context, which isolates the signature check from the
// AEAD check. Production callers pass nil.
func seal(inner *SealedInner, recipient *EncKey, sign SignFunc, hook func(fieldMap)) ([]byte, error) {
	if inner == nil || recipient == nil || sign == nil {
		return nil, fail(ReasonInvalidInput, "nil inner, recipient or signer")
	}
	if err := inner.checkForSeal(); err != nil {
		return nil, err
	}
	p := params(recipient.Suite)
	if p == nil {
		return nil, fail(ReasonUnknownSuite, "recipient key suite %d", recipient.Suite)
	}
	if err := recipient.check(); err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "recipient key")
	}
	pk, err := p.kem.NewPublicKey(recipient.Pub)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "recipient public key")
	}
	info, err := HPKEInfo(inner.To, recipient.Suite, recipient.KID)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "hpke info")
	}
	enc, sender, err := hpke.NewSender(pk, p.kdf, p.aead, info)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "hpke sender")
	}
	fields, err := inner.fieldMap()
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "encode inner")
	}
	pre, err := sigPreimage(fields, enc, recipient.KID, recipient.Suite)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "signature preimage")
	}
	sig, seq := sign(pre)
	if seq != inner.KeyStateSeq {
		return nil, fail(ReasonInvalidInput, "signer used key_state_seq %d, inner declares %d", seq, inner.KeyStateSeq)
	}
	if len(sig) != SigLen {
		return nil, fail(ReasonInvalidInput, "signer returned %d signature bytes, want %d", len(sig), SigLen)
	}
	if fields[keySig], err = encodeField(sig); err != nil {
		return nil, failWrap(ReasonInternalError, err, "encode sig")
	}
	want := applyPad(fields)
	if hook != nil {
		hook(fields)
	}
	pt, err := coredet.Marshal(fields)
	if err != nil {
		return nil, failWrap(ReasonInternalError, err, "encode inner")
	}
	if hook == nil && len(pt) != want {
		return nil, fail(ReasonInternalError, "padded inner is %d bytes, computed %d", len(pt), want)
	}
	ct, err := sender.Seal(nil, pt)
	if err != nil {
		return nil, failWrap(ReasonInternalError, err, "hpke seal")
	}
	env := SealedEnvelope{V: EnvelopeVersion, To: inner.To, Suite: recipient.Suite, KID: recipient.KID, Enc: enc, CT: ct}
	b, err := env.Marshal()
	if err != nil {
		return nil, failWrap(ReasonInternalError, err, "encode envelope")
	}
	return b, nil
}

// checkForSeal rejects an inner that its receiver would reject for reasons
// visible without a clock or a KEL replay.
func (in *SealedInner) checkForSeal() error {
	switch {
	case in.From == "" || in.To == "" || in.Type == "":
		return fail(ReasonInvalidInput, "from, to and type are required")
	case len(in.MID) != MIDLen:
		return fail(ReasonInvalidInput, "mid is %d bytes, want %d", len(in.MID), MIDLen)
	case in.TS == 0:
		return fail(ReasonInvalidInput, "ts is 0")
	case in.Exp < in.TS || in.Exp-in.TS > MaxMessageLifetimeMS:
		return fail(ReasonInvalidInput, "exp - ts outside [0, %d]", MaxMessageLifetimeMS)
	case len(in.Keys) == 0:
		return fail(ReasonInvalidInput, "keys is required on every message")
	}
	if _, err := ParseKEL(in.KEL); err != nil {
		return failWrap(ReasonInvalidInput, err, "kel")
	}
	for k := range in.Ext {
		if k < FirstIgnorableKey {
			return fail(ReasonInvalidInput, "extension key %d is below %d", k, FirstIgnorableKey)
		}
	}
	return nil
}

// fieldMap encodes the signed fields of in (everything except sig and pad)
// into a field map.
func (in *SealedInner) fieldMap() (fieldMap, error) {
	m := make(fieldMap, 13+len(in.Ext))
	for _, f := range []struct {
		k uint64
		v any
	}{
		{keyFrom, in.From}, {keySeq, in.KeyStateSeq}, {keyTo, in.To},
		{keyType, in.Type}, {keyIX, in.IX}, {keyMID, in.MID},
		{keyTS, in.TS}, {keyExp, in.Exp}, {keyBody, in.Body},
		{keyKEL, in.KEL}, {keyKeys, in.Keys},
	} {
		raw, err := encodeField(f.v)
		if err != nil {
			return nil, fmt.Errorf("field %d: %w", f.k, err)
		}
		m[f.k] = raw
	}
	for k, v := range in.Ext {
		// The value is copied into the signed map as given, so it must be
		// exactly one well-formed CBOR item; otherwise the map encoding
		// would be corrupt.
		var probe any
		if err := coredet.Unmarshal(v, &probe); err != nil {
			return nil, fmt.Errorf("extension %d is not one CBOR item: %w", k, err)
		}
		m[k] = append([]byte(nil), v...)
	}
	return m, nil
}

// Opened is the result of Open.
type Opened struct {
	Outer SealedEnvelope
	Inner SealedInner
	// KEL is Inner.KEL decoded under MaxKELBytes and MaxKELEvents. It has
	// not been replayed. The caller compares it with its stored KEL for the
	// sender (§3.6 step 6) and passes the resolved KEL to VerifyInnerSig.
	KEL []identity.SignedEvent
	// Preimage is the signature preimage of §3.3, built from the decrypted
	// field map. It is the input VerifyInnerSig checks Inner.Sig against.
	Preimage []byte
}

// Open performs §3.6 steps 1 to 4 on an envelope addressed to selfAID:
//
//  1. ParseOuter, then outer to == selfAID.
//  2. Look up kid in ring.
//  3. HPKE open with info = HPKEInfo(to, suite, kid) and empty aad.
//  4. Decode the plaintext as a field map; reject unknown keys in 0-63 and
//     missing or mistyped known keys; require inner to == outer to, a
//     16-byte mid, a 64-byte sig and an all-zero pad; decode the KEL under
//     the size caps; build the signature preimage.
//
// It does not check time (CheckTime), resolve the sender's KEL, or verify
// the signature (VerifyInnerSig). Every error is a *Error; all are
// permanent for the given bytes.
func Open(envelope []byte, selfAID string, ring KeyRing) (*Opened, error) {
	outer, err := ParseOuter(envelope)
	if err != nil {
		return nil, err
	}
	if outer.To != selfAID {
		return nil, fail(ReasonWrongRecipient, "to %s", outer.To)
	}
	if ring == nil {
		return nil, fail(ReasonUnknownKey, "no key ring")
	}
	kp, ok := ring.Key(outer.KID)
	if !ok || kp == nil {
		return nil, fail(ReasonUnknownKey, "kid %x", outer.KID)
	}
	if kp.Public.Suite != outer.Suite || !bytes.Equal(kp.Public.KID, outer.KID) {
		return nil, fail(ReasonUnknownKey, "key ring returned a different key for kid %x", outer.KID)
	}
	p := params(outer.Suite)
	sk, err := p.kem.NewPrivateKey(kp.Private)
	if err != nil {
		return nil, failWrap(ReasonDecrypt, err, "key ring private key")
	}
	info, err := HPKEInfo(outer.To, outer.Suite, outer.KID)
	if err != nil {
		return nil, failWrap(ReasonBadOuter, err, "hpke info")
	}
	r, err := hpke.NewRecipient(outer.Enc, sk, p.kdf, p.aead, info)
	if err != nil {
		return nil, failWrap(ReasonDecrypt, err, "hpke recipient")
	}
	pt, err := r.Open(nil, outer.CT)
	if err != nil {
		return nil, failWrap(ReasonDecrypt, err, "hpke open")
	}
	fields, inner, err := decodeInner(pt)
	if err != nil {
		return nil, err
	}
	if inner.To != outer.To {
		return nil, fail(ReasonToMismatch, "inner to %s, outer to %s", inner.To, outer.To)
	}
	kel, err := ParseKEL(inner.KEL)
	if err != nil {
		return nil, err
	}
	pre, err := sigPreimage(fields, outer.Enc, outer.KID, outer.Suite)
	if err != nil {
		return nil, failWrap(ReasonBadInner, err, "signature preimage")
	}
	return &Opened{Outer: *outer, Inner: *inner, KEL: kel, Preimage: pre}, nil
}

// decodeInner is §3.6 step 4 without the to comparison.
func decodeInner(pt []byte) (fieldMap, *SealedInner, error) {
	fields, err := decodeFields(pt)
	if err != nil {
		return nil, nil, failWrap(ReasonBadInner, err, "decode")
	}
	if k, ok := firstUnknownCritical(fields, innerKnown); ok {
		return nil, nil, fail(ReasonUnknownField, "inner key %d", k)
	}
	var in SealedInner
	var errs []error
	text := func(k uint64, dst *string) {
		v, err := rawText(fields, k)
		*dst = v
		errs = append(errs, err)
	}
	unum := func(k uint64, dst *uint64) {
		v, err := rawUint(fields, k)
		*dst = v
		errs = append(errs, err)
	}
	byts := func(k uint64, dst *[]byte) {
		v, err := rawBytes(fields, k)
		*dst = v
		errs = append(errs, err)
	}
	text(keyFrom, &in.From)
	unum(keySeq, &in.KeyStateSeq)
	text(keyTo, &in.To)
	text(keyType, &in.Type)
	text(keyIX, &in.IX)
	byts(keyMID, &in.MID)
	unum(keyTS, &in.TS)
	unum(keyExp, &in.Exp)
	byts(keyBody, &in.Body)
	byts(keyKEL, &in.KEL)
	byts(keyKeys, &in.Keys)
	byts(keySig, &in.Sig)
	for _, err := range errs {
		if err != nil {
			return nil, nil, failWrap(ReasonBadInner, err, "")
		}
	}
	if _, ok := fields[keyPad]; ok {
		if in.Pad, err = rawBytes(fields, keyPad); err != nil {
			return nil, nil, failWrap(ReasonBadInner, err, "")
		}
		for _, b := range in.Pad {
			if b != 0 {
				return nil, nil, fail(ReasonBadPad, "pad has a non-zero byte")
			}
		}
	}
	switch {
	case len(in.MID) != MIDLen:
		return nil, nil, fail(ReasonBadInner, "mid is %d bytes, want %d", len(in.MID), MIDLen)
	case len(in.Sig) != SigLen:
		return nil, nil, fail(ReasonBadInner, "sig is %d bytes, want %d", len(in.Sig), SigLen)
	}
	for k, v := range fields {
		if k >= FirstIgnorableKey {
			if in.Ext == nil {
				in.Ext = make(map[uint64][]byte)
			}
			in.Ext[k] = append([]byte(nil), v...)
		}
	}
	return fields, &in, nil
}

// CheckTime is §3.6 step 5: now <= exp, ts <= now + ClockSkewMS, and
// 0 <= exp - ts <= MaxMessageLifetimeMS. now is unix ms.
func CheckTime(inner *SealedInner, now uint64) error {
	if inner == nil {
		return fail(ReasonBadInner, "nil inner")
	}
	if inner.Exp < inner.TS || inner.Exp-inner.TS > MaxMessageLifetimeMS {
		return fail(ReasonBadLifetime, "exp - ts outside [0, %d]", MaxMessageLifetimeMS)
	}
	if now > inner.Exp {
		return fail(ReasonExpired, "now %d > exp %d", now, inner.Exp)
	}
	if inner.TS > satAdd(now, ClockSkewMS) {
		return fail(ReasonFromFuture, "ts %d > now %d + %d", inner.TS, now, ClockSkewMS)
	}
	return nil
}

// DefaultRotationGrace is the rotation grace of §3.6 step 7.
const DefaultRotationGrace = time.Hour

// VerifyInnerSig is §3.6 step 7. kel is the sender KEL resolved in step 6
// (the stored KEL or the one carried in the message); preimage is
// Opened.Preimage. now is unix ms.
//
// The KEL must replay to inner.From. The signature is checked with
// identity.VerifyObject at msgTime = inner.TS, which selects the key at the
// declared key_state_seq and, for a key state that a later rot or dip
// retired, requires that the retiring event carries a timestamp
// SupersededAt and inner.TS < SupersededAt. Then:
//   - A signature by an active key state (the key in force at the KEL head,
//     AID not deactivated) is accepted.
//   - A signature by a retired key state is accepted only when, in
//     addition, now - SupersededAt <= rotationGrace. The grace lets
//     messages sealed just before a rotation, and still in a mailbox, be
//     delivered; its cost is that a stolen pre-rotation key can sign
//     messages back-dated before the rotation for that long.
//
// Retirement is read from identity.Replay, which marks every key state that
// a later rot or dip retired, including across intervening ixn and drt
// events (A2A-DESIGN §3.6 [C4a]).
func VerifyInnerSig(inner *SealedInner, preimage []byte, kel []identity.SignedEvent, now uint64, rotationGrace time.Duration) error {
	if inner == nil {
		return fail(ReasonBadInner, "nil inner")
	}
	if inner.TS == 0 {
		// identity.VerifyObject treats msgTime 0 as "unknown" and applies a
		// weaker revocation gate; a message always has a time.
		return fail(ReasonBadInner, "ts is 0")
	}
	if len(inner.Sig) != SigLen {
		return fail(ReasonBadInner, "sig is %d bytes, want %d", len(inner.Sig), SigLen)
	}
	states, err := identity.Replay(kel)
	if err != nil {
		return failWrap(ReasonBadKEL, err, "replay")
	}
	if aid := states[len(states)-1].AID; aid != inner.From {
		return fail(ReasonFromMismatch, "KEL replays to %s, inner from %s", aid, inner.From)
	}
	seq := inner.KeyStateSeq
	if seq >= uint64(len(states)) {
		return fail(ReasonBadKeyState, "key_state_seq %d beyond KEL of %d events", seq, len(states))
	}
	if err := identity.VerifyObject(kel, inner.From, seq, inner.TS, preimage, inner.Sig); err != nil {
		return fromVErr(err)
	}
	ks := states[seq]
	if ks.Status == identity.StatusActive {
		return nil
	}
	// Retired: VerifyObject has established ks.SupersededAt != 0 and
	// inner.TS < ks.SupersededAt.
	grace := uint64(0)
	if rotationGrace > 0 {
		grace = uint64(rotationGrace / time.Millisecond)
	}
	if sup := ks.SupersededAt; now > sup && now-sup > grace {
		return fail(ReasonGraceExpired, "now %d is %d ms after retirement at %d; grace %d ms", now, now-sup, sup, grace)
	}
	return nil
}

// VerifyInnerKeys is §3.6 step 8: decode the sender's key set carried in
// the message and verify it with expectAID = inner.From against the
// resolved KEL. The result is advisory; a failure here does not invalidate
// the message. The caller applies DecideHighWater before storing it.
func VerifyInnerKeys(inner *SealedInner, kel []identity.SignedEvent, now uint64) (*SignedEncKeySet, *EncKeySet, error) {
	if inner == nil {
		return nil, nil, fail(ReasonBadInner, "nil inner")
	}
	signed, err := UnmarshalSignedEncKeySet(inner.Keys)
	if err != nil {
		return nil, nil, err
	}
	set, err := VerifyEncKeySet(signed, inner.From, kel, now)
	if err != nil {
		return nil, nil, err
	}
	return signed, set, nil
}
