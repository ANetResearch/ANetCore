package seal

import (
	"bytes"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/fxamacker/cbor/v2"
)

// EnvelopeVersion is the only outer version this package reads and writes
// (core §1.1 V3, outer key 1). There is no decoding path for any other
// version (CORE-V2).
const EnvelopeVersion = 2

// HPKELabel is the value of layer-1 HPKE info key 1 (core §3.2 L1). The
// layer-2 label is IXLabel.
const HPKELabel = "anet-seal/v2"

// DAckExporterContext is the HPKE exporter context of the ack_key (core §3.2
// L11): ack_key = Export(layer-1 context, "anet-dack/v1", 32).
const DAckExporterContext = "anet-dack/v1"

// AckKeyLen is the length of an ack_key.
const AckKeyLen = 32

// AckKey is the key a recipient derives a delivery token from (DLV §2.6.1).
// Seal exports it from the layer-1 sender context and returns it with the
// envelope; Open exports the same bytes from the recipient context as soon as
// layer 1 opens. The token functions (Handle, MakeDAck, VerifyDAck) are
// methods and functions of seal/dack.go.
type AckKey [AckKeyLen]byte

// Inner message types (core §2.4.1). The body of each is defined in the
// delegation package; this package carries the body as opaque bytes and
// does not restrict the type.
const (
	TypeDelegate = "anet.delegate/1" // DelegateReq, requester -> provider
	TypeMessage  = "anet.message/1"  // ChatMsg, both directions
	TypeStatus   = "anet.status/1"   // StatusMsg, provider -> requester
	TypeResult   = "anet.result/1"   // ResultResp, provider -> requester
)

// Outer envelope keys (core §2.1).
const (
	outerKeyV      = 1
	outerKeyTo     = 2
	outerKeySuite  = 3
	outerKeyKID    = 4
	outerKeyEnc    = 5
	outerKeyCT     = 6
	outerKeyAccess = 7
	outerKeyExp    = 8
)

// outerKnown is {1..8} (CORE-K1). Keys 0 and 9-63 are unknown-critical-field;
// keys >= 64 are skipped but stay inside env_digest.
var outerKnown = map[uint64]bool{
	outerKeyV: true, outerKeyTo: true, outerKeySuite: true, outerKeyKID: true,
	outerKeyEnc: true, outerKeyCT: true, outerKeyAccess: true, outerKeyExp: true,
}

// Wrap keys (core §2.2): the layer-1 plaintext.
const (
	wrapKeyIKID = 1  // with a second layer: KID(suite2, rk.pub)
	wrapKeyEnc2 = 2  // with a second layer: the layer-2 HPKE enc
	wrapKeyBody = 3  // the layer-2 ciphertext, or coredet(SealedInner)
	wrapKeyPad  = 21 // zero bytes that put the Wrap on a Padmé length
)

var wrapKnown = map[uint64]bool{wrapKeyIKID: true, wrapKeyEnc2: true, wrapKeyBody: true, wrapKeyPad: true}

// Inner message keys (core §2.3).
const (
	keyFrom   = 1
	keySeq    = 2
	keyTo     = 3
	keyType   = 4
	keyIX     = 5
	keyMID    = 6
	keyTS     = 7
	keyExp    = 8
	keyBody   = 9
	keyKEL    = 10
	keyNotice = 11
	keyKeys   = 12
	keyGrant  = 14
	keyRK     = 15
	keySig    = 20
)

// innerKnown are the keys 0-63 a v2 inner may carry. Everything else below
// FirstIgnorableKey is unknown-critical-field: the reserved keys, the retired
// 21 (the pad moved to the Wrap) and the preimage-only 0 and 30-34.
var innerKnown = map[uint64]bool{
	keyFrom: true, keySeq: true, keyTo: true, keyType: true, keyIX: true,
	keyMID: true, keyTS: true, keyExp: true, keyBody: true, keyKEL: true,
	keyNotice: true, keyKeys: true, keyGrant: true, keyRK: true, keySig: true,
}

// MaxNoticeBytes caps each witness notice an inner carries in key 11 (KEL
// §2.6); a typical notice is about 250 bytes.
const MaxNoticeBytes = 1024

// noticesPerMessage is the length of inner key 11 in 0.3.0 (core §2.3): one
// notice, from the sender's one witness.
const noticesPerMessage = 1

// Access kinds (core §2.1, outer key 7, Access key 1).
const (
	// AccessKindSession is a first-contact delivery under a hub session
	// (the session MAC travels in HTTP headers, not here).
	AccessKindSession uint64 = 0
	// AccessKindCap is a delivery under a capability the recipient issued,
	// with the holder's proof of possession over env_digest.
	AccessKindCap uint64 = 1
	// Kind 2 is reserved for an anonymous first-contact token and refused
	// in 0.3.0.
)

// Access is the delivery credential in outer key 7 (core §2.1). It is outside
// the HPKE info, the inner signature and env_digest, so a sender can change it
// without sealing again (SSR-W2). This package checks its structure; the
// credential itself is checked by VerifyAccess (SS-1) and the hub.
//
//anet:wire Access
type Access struct {
	Kind  uint64 `cbor:"1,keyasint"`           // AccessKind*
	Cap   *Cap   `cbor:"2,keyasint,omitempty"` // kind 1 only
	Proof []byte `cbor:"3,keyasint,omitempty"` // kind 1 only: SigLen bytes, the holder's proof (L5)
}

// Cap is a capability as carried on the wire (core §2.1): the CoreDet bytes of
// a CapBody and the mailbox key's signature over them.
//
//anet:wire Cap
type Cap struct {
	Body []byte `cbor:"1,keyasint"` // coredet(CapBody)
	Sig  []byte `cbor:"2,keyasint"` // SigLen bytes
}

// SealedEnvelope is the outer object, the only part a hub sees (core §2.1).
// ParseOuter fills Access and Exp from keys 7 and 8; keys >= 64 are not kept
// here (EnvDigest reads them from the bytes).
//
//anet:wire SealedEnvelope
type SealedEnvelope struct {
	V      uint64  `cbor:"1,keyasint"` // EnvelopeVersion
	To     string  `cbor:"2,keyasint"` // recipient AID
	Suite  Suite   `cbor:"3,keyasint"`
	KID    []byte  `cbor:"4,keyasint"` // KIDLen bytes, the recipient epoch key sealed to
	Enc    []byte  `cbor:"5,keyasint"` // layer-1 HPKE encapsulated key
	CT     []byte  `cbor:"6,keyasint"` // layer-1 ciphertext of the Wrap
	Access *Access `cbor:"7,keyasint,omitempty"`
	// Exp is outer key 8, the expiry of a one-shot envelope; nil when the
	// key is absent. When present it equals the inner exp (Open checks).
	Exp *uint64 `cbor:"8,keyasint,omitempty"`
}

// Marshal returns the CoreDet encoding of e. With Access nil the result is
// what Seal returns: an envelope still without its credential.
func (e *SealedEnvelope) Marshal() ([]byte, error) { return coredet.Marshal(*e) }

// SealedInner is the plaintext a sender signs (core §2.3).
//
// The struct has no CBOR tags on purpose. The wire form is built by Seal as
// an integer-keyed field map, so that the signature preimage is computed
// over exactly the values that are sent, including extension keys. The field
// numbers are given in the comments. A nil slice or pointer is an absent key;
// which types must carry keys 10, 12, 14 and 15 is the daemon's rule
// (CORE-K3), not this package's.
type SealedInner struct {
	From        string // 1: sender AID; no U+0000
	KeyStateSeq uint64 // 2: sender key_state_seq the signature was made under
	To          string // 3: recipient AID; must equal the outer to; no U+0000
	Type        string // 4: Type* constant
	IX          string // 5: interaction id; no U+0000
	MID         []byte // 6: message id, MIDLen bytes; the replay key with From
	TS          uint64 // 7: send time, unix ms
	Exp         uint64 // 8: expiry, unix ms; exp - ts <= MaxMessageLifetimeMS
	Body        []byte // 9: type-specific payload; the preimage holds its SHA-256
	KEL         []byte // 10: sender KEL (identity.MarshalKEL), within MaxKELBytes / MaxKELEvents
	// Notices is key 11: the witness notices for the KEL, each a
	// coredet(NoticeWire) of at most MaxNoticeBytes. Present exactly when
	// KEL is, and then exactly one (C-52, C-53). CheckNotice (KEL-4) checks
	// the content.
	Notices [][]byte
	Keys    []byte // 12: sender SignedEncKeySet encoding
	// Grant is key 14 as one CBOR item: a Grant map the sender issues to the
	// recipient. Open keeps it as received whatever it holds; a grant that
	// does not decode or check is ignored, never a reason to refuse the
	// message (CORE-K4; CheckGrant, SS-1).
	Grant cbor.RawMessage
	RK    *RK    // 15: the sender's interaction key in this interaction
	Sig   []byte // 20: Ed25519 over the preimage; set by Seal

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

// hpkeInfo is the HPKE info map of either layer (core §3.2 L1, L2).
//
//anet:wire HPKEInfo
type hpkeInfo struct {
	Label string `cbor:"1,keyasint"`
	To    string `cbor:"2,keyasint"`
	Suite Suite  `cbor:"3,keyasint"`
	KID   []byte `cbor:"4,keyasint"`
}

// HPKEInfo returns the layer-1 HPKE info of an envelope (L1):
// coredet({1: "anet-seal/v2", 2: to, 3: suite, 4: kid}). It binds the key
// schedule to the recipient AID and epoch key, so a ciphertext cannot be moved
// to another envelope header without the AEAD failing. aad is empty.
func HPKEInfo(to string, suite Suite, kid []byte) ([]byte, error) {
	return coredet.Marshal(hpkeInfo{HPKELabel, to, suite, kid})
}

// decodeAccess is the structural check of outer key 7 (SSR-W5): a map with no
// key but 1, 2 and 3 (Access has no extension range, CORE-E3); kind 0 with
// neither cap nor proof, or kind 1 with both; cap a map with exactly a byte
// string body and a SigLen-byte sig; proof SigLen bytes. Kind 2 and every
// other value are refused. CapBody is not decoded here (VerifyAccess, SS-1).
func decodeAccess(raw []byte) (*Access, error) {
	m, err := decodeFields(raw)
	if err != nil {
		return nil, fmt.Errorf("access: %w", err)
	}
	for k := range m {
		if k < 1 || k > 3 {
			return nil, fmt.Errorf("access has key %d", k)
		}
	}
	var a Access
	if a.Kind, err = rawUint(m, 1); err != nil {
		return nil, fmt.Errorf("access kind: %w", err)
	}
	_, hasCap := m[2]
	_, hasProof := m[3]
	switch a.Kind {
	case AccessKindSession:
		if hasCap || hasProof {
			return nil, fmt.Errorf("access kind 0 carries a capability or a proof")
		}
		return &a, nil
	case AccessKindCap:
		if !hasCap || !hasProof {
			return nil, fmt.Errorf("access kind 1 needs both a capability and a proof")
		}
	default:
		return nil, fmt.Errorf("access kind %d is not 0 or 1", a.Kind)
	}
	cm, err := decodeFields(m[2])
	if err != nil {
		return nil, fmt.Errorf("access cap: %w", err)
	}
	for k := range cm {
		if k < 1 || k > 2 {
			return nil, fmt.Errorf("access cap has key %d", k)
		}
	}
	var c Cap
	if c.Body, err = rawBytes(cm, 1); err != nil {
		return nil, fmt.Errorf("access cap body: %w", err)
	}
	if c.Sig, err = rawBytes(cm, 2); err != nil {
		return nil, fmt.Errorf("access cap sig: %w", err)
	}
	if len(c.Sig) != SigLen {
		return nil, fmt.Errorf("access cap sig is %d bytes, want %d", len(c.Sig), SigLen)
	}
	a.Cap = &c
	if a.Proof, err = rawBytes(m, 3); err != nil {
		return nil, fmt.Errorf("access proof: %w", err)
	}
	if len(a.Proof) != SigLen {
		return nil, fmt.Errorf("access proof is %d bytes, want %d", len(a.Proof), SigLen)
	}
	return &a, nil
}

// encodeAccess checks a the way decodeAccess does and returns its encoding.
func encodeAccess(a *Access) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("no access")
	}
	b, err := coredet.Marshal(a)
	if err != nil {
		return nil, err
	}
	if _, err := decodeAccess(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ParseOuter decodes an envelope and applies the structural checks a hub
// makes before accepting it for relay and a daemon makes as receive step 1,
// in this order:
//
//  1. a CBOR map with unsigned keys (bad-outer); v == 2 (bad-version);
//  2. no key 0 or 9-63 (unknown-critical-field; keys >= 64 are skipped);
//  3. key 7 present and a well-formed Access (access-invalid, Detail "parse");
//  4. key 8, when present, an unsigned integer (bad-outer);
//  5. a non-empty to, a suite this build implements (unknown-suite), a
//     16-byte kid, an enc of the suite's length and a non-empty ct
//     (bad-outer).
//
// It does not compare to with any AID (the hub compares it with the
// recipient it routes to, Open with the local AID) and does not check the
// credential in key 7 (VerifyAccess). Every failure is a *Error without an
// ack_key.
func ParseOuter(envelope []byte) (*SealedEnvelope, error) {
	fields, err := decodeFields(envelope)
	if err != nil {
		return nil, failWrap(ReasonBadOuter, err, "decode")
	}
	// The version is checked before the other fields: another version may
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
	raw, ok := fields[outerKeyAccess]
	if !ok {
		// Detail is the step name alone (SSR-W5); the cause goes in Err.
		return nil, failWrap(ReasonAccessInvalid, errors.New("outer key 7 (access) is missing"), "parse")
	}
	if e.Access, err = decodeAccess(raw); err != nil {
		return nil, failWrap(ReasonAccessInvalid, err, "parse")
	}
	if _, ok := fields[outerKeyExp]; ok {
		exp, err := rawUint(fields, outerKeyExp)
		if err != nil {
			return nil, failWrap(ReasonBadOuter, err, "")
		}
		e.Exp = &exp
	}
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

// envDigestLabel is the prefix of env_digest (core §3.2 L4, a B-class input:
// label, 0x00, then the encoded fields).
const envDigestLabel = "anet-env/v2\x00"

// EnvDigest returns env_digest (core §3.2 L4): SHA-256("anet-env/v2" || 0x00 ||
// coredet(the outer fields without key 7)), the fields taken as received and
// only their keys put in order. It does not look at key 7, so an envelope
// before and after SetAccess has the same digest; any other change, including
// key 8 and the keys >= 64, changes it (SSR-W1). It checks only that env is a
// map with unsigned keys (bad-outer); ParseOuter is the structural check.
func EnvDigest(env []byte) ([32]byte, error) {
	fields, err := decodeFields(env)
	if err != nil {
		return [32]byte{}, failWrap(ReasonBadOuter, err, "decode")
	}
	delete(fields, outerKeyAccess)
	b, err := coredet.Marshal(fields)
	if err != nil {
		return [32]byte{}, failWrap(ReasonBadOuter, err, "encode")
	}
	h := sha256.New()
	h.Write([]byte(envDigestLabel))
	h.Write(b)
	var d [32]byte
	h.Sum(d[:0])
	return d, nil
}

// SetAccess writes or replaces outer key 7 of env with a and returns the new
// envelope. The other fields keep their bytes, so EnvDigest does not change
// (ENG-I2: a sender sets a fresh credential on each attempt without sealing
// again). a must be well-formed (invalid-input otherwise), and the result
// must pass ParseOuter; its error is returned when it does not.
func SetAccess(env []byte, a *Access) ([]byte, error) {
	raw, err := encodeAccess(a)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "access")
	}
	fields, err := decodeFields(env)
	if err != nil {
		return nil, failWrap(ReasonBadOuter, err, "decode")
	}
	fields[outerKeyAccess] = raw
	out, err := coredet.Marshal(fields)
	if err != nil {
		return nil, failWrap(ReasonBadOuter, err, "encode")
	}
	if _, err := ParseOuter(out); err != nil {
		return nil, err
	}
	return out, nil
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

// SealOpts are the options of Seal (core §4.4).
type SealOpts struct {
	// PeerRK is the interaction key the recipient announced in this
	// interaction (its rk): non-nil seals a second layer to it, nil seals one
	// layer (FS-X5).
	PeerRK *RK
	// Exp is outer key 8: 0 leaves the key out (every queued message);
	// otherwise it must equal the inner exp (a one-shot envelope, core G11).
	Exp uint64
}

// Seal signs inner and encrypts it to recipient (core §4.4). It returns the
// envelope without outer key 7 (the caller adds the credential with
// SetAccess on each attempt, CORE-A3) and the ack_key of the envelope, the
// key the recipient's delivery token is made under (DLV-C-1).
//
// The caller fills every field except Sig, which Seal sets (a value present
// in the input is ignored). inner.KeyStateSeq must be the seq the signer will
// sign under (for an identity.Controller, CurrentSeq()); Seal checks it
// against what sign returns, because the seq is inside the signed preimage
// and a rotation between the two calls would otherwise produce a signature
// that no receiver accepts.
//
// With o.PeerRK set, Seal adds a second layer sealed to the recipient's
// interaction key (FS-C17): it sets up both HPKE sender contexts first, so
// the signature covers enc, ikid and enc2; then it encrypts the inner under
// the layer-2 context (info IXInfo, not padded), puts ikid, enc2 and that
// ciphertext in the Wrap, pads the Wrap and encrypts it under layer 1. The
// ack_key is the layer-1 export either way (FS-C14).
//
// The signature covers the layer-1 enc, so Seal signs after the HPKE sender
// context exists. The result is randomized: sealing the same inner twice
// gives different bytes and a different ack_key. A retry of one envelope
// resends the bytes from the first call.
func Seal(inner *SealedInner, recipient *EncKey, sign SignFunc, o SealOpts) ([]byte, AckKey, error) {
	return seal(inner, recipient, sign, o, nil)
}

// sealHooks let tests alter what Seal builds after it signed, keeping the
// HPKE context, so a rule can be tested in isolation from the signature or
// the AEAD. Production callers pass nil.
type sealHooks struct {
	inner func(fieldMap) // the signed inner field map, before encoding
	wrap  func(fieldMap) // the padded Wrap, before encryption
	outer func(fieldMap) // the outer, before encoding
}

func seal(inner *SealedInner, recipient *EncKey, sign SignFunc, o SealOpts, hooks *sealHooks) ([]byte, AckKey, error) {
	// ack stays zero on every error return; the export goes to key and is
	// returned only with the envelope it belongs to.
	var ack, key AckKey
	if inner == nil || recipient == nil || sign == nil {
		return nil, ack, fail(ReasonInvalidInput, "nil inner, recipient or signer")
	}
	if err := inner.checkForSeal(o); err != nil {
		return nil, ack, err
	}
	p := params(recipient.Suite)
	if p == nil {
		return nil, ack, fail(ReasonUnknownSuite, "recipient key suite %d", recipient.Suite)
	}
	if err := recipient.check(); err != nil {
		return nil, ack, failWrap(ReasonInvalidInput, err, "recipient key")
	}
	pk, err := p.kem.NewPublicKey(recipient.Pub)
	if err != nil {
		return nil, ack, failWrap(ReasonInvalidInput, err, "recipient public key")
	}
	info, err := HPKEInfo(inner.To, recipient.Suite, recipient.KID)
	if err != nil {
		return nil, ack, failWrap(ReasonInvalidInput, err, "hpke info")
	}
	enc, sender, err := hpke.NewSender(pk, p.kdf, p.aead, info)
	if err != nil {
		return nil, ack, failWrap(ReasonInvalidInput, err, "hpke sender")
	}
	exported, err := sender.Export(DAckExporterContext, AckKeyLen)
	if err != nil {
		return nil, ack, failWrap(ReasonInternalError, err, "export ack_key")
	}
	copy(key[:], exported)
	// The second layer's sender context, before anything is signed: its enc2
	// is in the preimage (FS-C17).
	var two *layer2Sender
	if o.PeerRK != nil {
		if two, err = newLayer2Sender(inner.To, o.PeerRK); err != nil {
			return nil, ack, err
		}
	}
	fields, err := inner.fieldMap()
	if err != nil {
		return nil, ack, failWrap(ReasonInvalidInput, err, "encode inner")
	}
	var ikid, enc2 []byte
	if two != nil {
		ikid, enc2 = two.ikid, two.enc2
	}
	pre, err := sigPreimage(fields, enc, recipient.KID, recipient.Suite, ikid, enc2)
	if err != nil {
		return nil, ack, failWrap(ReasonInvalidInput, err, "signature preimage")
	}
	sig, seq := sign(pre)
	if seq != inner.KeyStateSeq {
		return nil, ack, fail(ReasonInvalidInput, "signer used key_state_seq %d, inner declares %d", seq, inner.KeyStateSeq)
	}
	if len(sig) != SigLen {
		return nil, ack, fail(ReasonInvalidInput, "signer returned %d signature bytes, want %d", len(sig), SigLen)
	}
	if fields[keySig], err = encodeField(sig); err != nil {
		return nil, ack, failWrap(ReasonInternalError, err, "encode sig")
	}
	if hooks != nil && hooks.inner != nil {
		hooks.inner(fields)
	}
	innerBytes, err := coredet.Marshal(fields)
	if err != nil {
		return nil, ack, failWrap(ReasonInternalError, err, "encode inner")
	}
	w := wrapFields{body: innerBytes}
	if two != nil {
		// The inner is the layer-2 plaintext as it is, without padding: only
		// the Wrap is padded (FS-C9, FS-C10).
		if w.body, err = two.sender.Seal(nil, innerBytes); err != nil {
			return nil, ack, failWrap(ReasonInternalError, err, "hpke seal, second layer")
		}
		w.ikid, w.enc2 = ikid, enc2
	}
	wrap, want, err := w.paddedMap()
	if err != nil {
		return nil, ack, failWrap(ReasonInternalError, err, "encode wrap")
	}
	if hooks != nil && hooks.wrap != nil {
		hooks.wrap(wrap)
	}
	pt, err := coredet.Marshal(wrap)
	if err != nil {
		return nil, ack, failWrap(ReasonInternalError, err, "encode wrap")
	}
	if (hooks == nil || hooks.wrap == nil) && len(pt) != want {
		return nil, ack, fail(ReasonInternalError, "padded wrap is %d bytes, computed %d", len(pt), want)
	}
	ct, err := sender.Seal(nil, pt)
	if err != nil {
		return nil, ack, failWrap(ReasonInternalError, err, "hpke seal")
	}
	outer := fieldMap{}
	for k, v := range map[uint64]any{
		outerKeyV: uint64(EnvelopeVersion), outerKeyTo: inner.To, outerKeySuite: uint64(recipient.Suite),
		outerKeyKID: recipient.KID, outerKeyEnc: enc, outerKeyCT: ct,
	} {
		if outer[k], err = encodeField(v); err != nil {
			return nil, ack, failWrap(ReasonInternalError, err, "encode envelope")
		}
	}
	if o.Exp != 0 {
		if outer[outerKeyExp], err = encodeField(o.Exp); err != nil {
			return nil, ack, failWrap(ReasonInternalError, err, "encode envelope")
		}
	}
	if hooks != nil && hooks.outer != nil {
		hooks.outer(outer)
	}
	b, err := coredet.Marshal(outer)
	if err != nil {
		return nil, ack, failWrap(ReasonInternalError, err, "encode envelope")
	}
	return b, key, nil
}

// checkForSeal rejects an inner, or options, that its receiver would reject
// for reasons visible without a clock or a KEL replay, and an input that
// cannot be encoded.
func (in *SealedInner) checkForSeal(o SealOpts) error {
	switch {
	case in.From == "" || in.To == "" || in.Type == "":
		return fail(ReasonInvalidInput, "from, to and type are required")
	case strings.ContainsRune(in.From, 0) || strings.ContainsRune(in.To, 0) || strings.ContainsRune(in.IX, 0):
		// CORE-E9: a receiver refuses these (bad-inner), so Seal does not
		// produce them.
		return fail(ReasonInvalidInput, "from, to and ix may not contain U+0000")
	case len(in.MID) != MIDLen:
		return fail(ReasonInvalidInput, "mid is %d bytes, want %d", len(in.MID), MIDLen)
	case in.TS == 0:
		return fail(ReasonInvalidInput, "ts is 0")
	case in.Exp < in.TS || in.Exp-in.TS > MaxMessageLifetimeMS:
		return fail(ReasonInvalidInput, "exp - ts outside [0, %d]", MaxMessageLifetimeMS)
	case o.Exp != 0 && o.Exp != in.Exp:
		return fail(ReasonInvalidInput, "outer exp %d is not the inner exp %d", o.Exp, in.Exp)
	case (in.KEL != nil) != (len(in.Notices) > 0):
		return fail(ReasonInvalidInput, "kel and notices go together (C-53)")
	}
	if in.KEL != nil {
		if len(in.Notices) != noticesPerMessage {
			return fail(ReasonInvalidInput, "%d notices, want %d", len(in.Notices), noticesPerMessage)
		}
		if _, err := ParseKEL(in.KEL); err != nil {
			return failWrap(ReasonInvalidInput, err, "kel")
		}
	}
	for _, n := range in.Notices {
		if len(n) > MaxNoticeBytes {
			return fail(ReasonInvalidInput, "a notice is %d bytes, cap %d", len(n), MaxNoticeBytes)
		}
	}
	if in.Grant != nil {
		if !wellFormedItem(in.Grant) || in.Grant[0]>>5 != majorMap {
			return fail(ReasonInvalidInput, "grant is not one CBOR map")
		}
	}
	if in.RK != nil {
		if err := in.RK.check(); err != nil {
			return failWrap(ReasonInvalidInput, err, "rk")
		}
	}
	for k, v := range in.Ext {
		if k < FirstIgnorableKey {
			return fail(ReasonInvalidInput, "extension key %d is below %d", k, FirstIgnorableKey)
		}
		// The value is copied into the signed map as given, so it must be
		// exactly one well-formed CBOR item; otherwise the map encoding
		// would be corrupt.
		if !wellFormedItem(v) {
			return fail(ReasonInvalidInput, "extension %d is not one CBOR item", k)
		}
	}
	return nil
}

// wellFormedItem reports whether b is exactly one CoreDet-decodable item.
func wellFormedItem(b []byte) bool {
	var probe any
	return len(b) > 0 && coredet.Unmarshal(b, &probe) == nil
}

// fieldMap encodes the signed fields of in (everything except sig) into a
// field map. checkForSeal has run.
func (in *SealedInner) fieldMap() (fieldMap, error) {
	m := make(fieldMap, 16+len(in.Ext))
	put := func(k uint64, v any) error {
		raw, err := encodeField(v)
		if err != nil {
			return fmt.Errorf("field %d: %w", k, err)
		}
		m[k] = raw
		return nil
	}
	for _, f := range []struct {
		k uint64
		v any
	}{
		{keyFrom, in.From}, {keySeq, in.KeyStateSeq}, {keyTo, in.To},
		{keyType, in.Type}, {keyIX, in.IX}, {keyMID, in.MID},
		{keyTS, in.TS}, {keyExp, in.Exp}, {keyBody, in.Body},
	} {
		if err := put(f.k, f.v); err != nil {
			return nil, err
		}
	}
	if in.KEL != nil {
		if err := put(keyKEL, in.KEL); err != nil {
			return nil, err
		}
	}
	if len(in.Notices) > 0 {
		notices := make([][]byte, len(in.Notices))
		for i, n := range in.Notices {
			notices[i] = n
			if n == nil {
				notices[i] = []byte{} // a byte string, not null
			}
		}
		if err := put(keyNotice, notices); err != nil {
			return nil, err
		}
	}
	if in.Keys != nil {
		if err := put(keyKeys, in.Keys); err != nil {
			return nil, err
		}
	}
	if in.Grant != nil {
		m[keyGrant] = append(cbor.RawMessage(nil), in.Grant...)
	}
	if in.RK != nil {
		if err := put(keyRK, in.RK); err != nil {
			return nil, err
		}
	}
	for k, v := range in.Ext {
		m[k] = append([]byte(nil), v...)
	}
	return m, nil
}

// Opened is the result of Open.
//
// CORE-A2 lists what an opened message carries beyond the v1 result: AckKey,
// Layers, IKID, RK, Notices, Grant and Access, each a field here. Access,
// RK, Notices and Grant are also in Outer and Inner, the forms Seal and
// ParseOuter use; Open sets both to the same values.
type Opened struct {
	Outer SealedEnvelope
	Inner SealedInner
	// KEL is Inner.KEL decoded under MaxKELBytes and MaxKELEvents, nil when
	// the inner carries no key 10. It has not been replayed. The caller
	// resolves it against its stored KEL for the sender (receive step 6) and
	// passes the result to VerifyInnerSig.
	KEL []identity.SignedEvent
	// Preimage is the signature preimage v2 (core §3.3), built from the
	// decrypted field map. It is the input VerifyInnerSig checks Inner.Sig
	// against.
	Preimage []byte
	// AckKey is the layer-1 export the delivery token of this envelope is
	// made under (DLV-C-2).
	AckKey AckKey
	// Layers is 1, or 2 when the Wrap carried a second layer and it opened
	// under this node's interaction key.
	Layers int
	// IKID is Wrap key 1, the kid of this node's interaction key the second
	// layer was sealed to; nil for one layer. The inner's (ix, from) is that
	// key's (ix, peer).
	IKID []byte
	// Access is outer key 7 as ParseOuter decoded it (Outer.Access). Its
	// structure is checked; the credential is not (VerifyAccess, SS-1).
	Access *Access
	// RK is inner key 15 (Inner.RK), nil when absent.
	RK *RK
	// Notices is inner key 11 (Inner.Notices): the witness notices for KEL,
	// nil exactly when KEL is. CheckNotice (KEL-4) checks the content.
	Notices [][]byte
	// Grant is inner key 14 as received (Inner.Grant), nil when absent. It
	// may not decode; CheckGrant (SS-1) decides whether to keep it (CORE-K4).
	Grant cbor.RawMessage
}

// Open performs receive steps 1 to 4 on an envelope addressed to selfAID, in
// this order (FS-C13, engine §4.2):
//
//  1. ParseOuter, then outer to == selfAID (wrong-recipient).
//  2. Look up kid in ring (sealed-to-unknown-key).
//  3. Layer-1 HPKE open, info HPKEInfo(to, suite, kid), empty aad
//     (decrypt-failed). From here on every error carries the ack_key
//     (AckKeyOf); none before does.
//     3a. Decode the Wrap (bad-wrap). With a second layer: look ikid up in
//     ix (nil ix, no key, or a key that is not the one of ikid:
//     sealed-to-closed-interaction; a lookup error is returned as it is,
//     with the ack_key and no seal reason), then open the second layer
//     under the key, info IXInfo(to, suite, ikid) (decrypt-failed).
//  4. Decode the inner strictly: no key 0-63 outside the v2 set
//     (unknown-critical-field); every key of its type and size, key 11
//     exactly with key 10, at most MaxNoticeBytes per notice, no U+0000 in
//     from, to or ix (bad-inner); a well-formed rk (bad-rk). Then, with a
//     second layer, the interaction key's (ix, peer) == the inner (ix,
//     from) (ikey-mismatch); inner to == outer to (to-mismatch); outer key
//     8, when present, == inner exp (exp-mismatch); the KEL under its caps
//     (kel-too-large, bad-kel); then the preimage, with the second layer's
//     ikid and enc2 (CBOR null for one layer).
//
// The ack_key comes from layer 1 whether or not there is a second layer
// (FS-C14). Opened.Layers and Opened.IKID say which it was.
//
// It does not check time (CheckTime), resolve the sender's KEL, check the
// witness notice, verify the signature (VerifyInnerSig) or enforce which
// keys a message type must carry (the daemon, receive step 4a). Every *Error
// it returns describes the given bytes and is permanent (the one exception, an
// internal error of the HPKE export, cannot happen).
func Open(envelope []byte, selfAID string, ring KeyRing, ix IXKeyLookup) (*Opened, error) {
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
	var ack AckKey
	exported, err := r.Export(DAckExporterContext, AckKeyLen)
	if err != nil {
		// Not reachable for a 32-byte export. Without the key no token can
		// be made, so this is an internal error, which is not permanent.
		return nil, failWrap(ReasonInternalError, err, "export ack_key")
	}
	copy(ack[:], exported)

	// Step 3a.
	w, err := decodeWrap(pt)
	if err != nil {
		return nil, withAck(ack, err)
	}
	innerPT, layers := w.body, 1
	var key *IXKey
	if w.ikid != nil {
		if ix != nil {
			if key, err = ix.IXKey(w.ikid); err != nil {
				return nil, withAck(ack, err)
			}
		}
		if key == nil {
			return nil, withAck(ack, fail(ReasonSealedToClosedInteraction, "ikid %x", w.ikid))
		}
		if err := key.answers(w.ikid); err != nil {
			return nil, withAck(ack, failWrap(ReasonSealedToClosedInteraction, err, "ikid %x", w.ikid))
		}
		if innerPT, err = openLayer2(outer.To, key, w); err != nil {
			return nil, withAck(ack, err)
		}
		layers = 2
	}

	// Step 4.
	fields, inner, err := decodeInner(innerPT)
	if err != nil {
		return nil, withAck(ack, err)
	}
	// The interaction key that opened the second layer belongs to one
	// interaction with one peer; a message of another interaction or from
	// another sender is not taken under it (FS-C13).
	if key != nil && (inner.IX != key.IX || inner.From != key.PeerAID) {
		return nil, withAck(ack, fail(ReasonIKeyMismatch, "inner (ix %q, from %s); interaction key of (ix %q, peer %s)",
			inner.IX, inner.From, key.IX, key.PeerAID))
	}
	if inner.To != outer.To {
		return nil, withAck(ack, fail(ReasonToMismatch, "inner to %s, outer to %s", inner.To, outer.To))
	}
	if outer.Exp != nil && *outer.Exp != inner.Exp {
		return nil, withAck(ack, fail(ReasonExpMismatch, "outer exp %d, inner exp %d", *outer.Exp, inner.Exp))
	}
	var kel []identity.SignedEvent
	if inner.KEL != nil {
		if kel, err = ParseKEL(inner.KEL); err != nil {
			return nil, withAck(ack, err)
		}
	}
	pre, err := sigPreimage(fields, outer.Enc, outer.KID, outer.Suite, w.ikid, w.enc2)
	if err != nil {
		return nil, withAck(ack, failWrap(ReasonBadInner, err, "signature preimage"))
	}
	return &Opened{
		Outer: *outer, Inner: *inner, KEL: kel, Preimage: pre, AckKey: ack, Layers: layers, IKID: w.ikid,
		Access: outer.Access, RK: inner.RK, Notices: inner.Notices, Grant: inner.Grant,
	}, nil
}

// wrapFields is a decoded Wrap.
type wrapFields struct {
	ikid, enc2 []byte // both nil for one layer
	body       []byte
}

// paddedMap returns the Wrap of w as a field map with its zero pad (FS-C9),
// and the length its encoding has: a Padmé length. decodeWrap of the encoded
// map gives w back (P-8).
func (w *wrapFields) paddedMap() (fieldMap, int, error) {
	if (w.ikid == nil) != (w.enc2 == nil) {
		return nil, 0, errors.New("ikid and enc2 go together")
	}
	m := fieldMap{}
	var err error
	if m[wrapKeyBody], err = encodeField(w.body); err != nil {
		return nil, 0, err
	}
	if w.ikid != nil {
		if m[wrapKeyIKID], err = encodeField(w.ikid); err != nil {
			return nil, 0, err
		}
		if m[wrapKeyEnc2], err = encodeField(w.enc2); err != nil {
			return nil, 0, err
		}
	}
	return m, applyPad(m), nil
}

// decodeWrap is the Wrap decode of FS-C8: a map; no key 0, 4-20 or 22-63
// (keys >= 64 are ignored); key 3 a byte string; keys 1 and 2 both or
// neither, ikid KIDLen bytes and enc2 of the suite's length; key 21 present
// and all zero bytes. Every failure is bad-wrap.
func decodeWrap(pt []byte) (*wrapFields, error) {
	m, err := decodeFields(pt)
	if err != nil {
		return nil, failWrap(ReasonBadWrap, err, "decode")
	}
	if k, ok := firstUnknownCritical(m, wrapKnown); ok {
		return nil, fail(ReasonBadWrap, "wrap key %d", k)
	}
	var w wrapFields
	if w.body, err = rawBytes(m, wrapKeyBody); err != nil {
		return nil, failWrap(ReasonBadWrap, err, "")
	}
	pad, err := rawBytes(m, wrapKeyPad)
	if err != nil {
		return nil, failWrap(ReasonBadWrap, err, "")
	}
	for _, b := range pad {
		if b != 0 {
			return nil, fail(ReasonBadWrap, "pad has a non-zero byte")
		}
	}
	_, hasIKID := m[wrapKeyIKID]
	_, hasEnc2 := m[wrapKeyEnc2]
	switch {
	case hasIKID != hasEnc2:
		return nil, fail(ReasonBadWrap, "ikid and enc2 go together")
	case hasIKID:
		if w.ikid, err = rawBytes(m, wrapKeyIKID); err != nil {
			return nil, failWrap(ReasonBadWrap, err, "")
		}
		if w.enc2, err = rawBytes(m, wrapKeyEnc2); err != nil {
			return nil, failWrap(ReasonBadWrap, err, "")
		}
		if len(w.ikid) != KIDLen {
			return nil, fail(ReasonBadWrap, "ikid is %d bytes, want %d", len(w.ikid), KIDLen)
		}
		if len(w.enc2) != params(SuiteX25519).encLen {
			return nil, fail(ReasonBadWrap, "enc2 is %d bytes, want %d", len(w.enc2), params(SuiteX25519).encLen)
		}
	}
	return &w, nil
}

// decodeInner is the strict inner decode of receive step 4, without the
// comparisons with the outer.
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
	optBytes := func(k uint64, dst *[]byte) {
		if _, ok := fields[k]; ok {
			byts(k, dst)
		}
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
	optBytes(keyKEL, &in.KEL)
	optBytes(keyKeys, &in.Keys)
	byts(keySig, &in.Sig)
	for _, err := range errs {
		if err != nil {
			return nil, nil, failWrap(ReasonBadInner, err, "")
		}
	}
	if _, ok := fields[keyNotice]; ok {
		if in.Notices, err = rawNotices(fields[keyNotice]); err != nil {
			return nil, nil, failWrap(ReasonBadInner, err, "")
		}
	}
	switch {
	case len(in.MID) != MIDLen:
		return nil, nil, fail(ReasonBadInner, "mid is %d bytes, want %d", len(in.MID), MIDLen)
	case len(in.Sig) != SigLen:
		return nil, nil, fail(ReasonBadInner, "sig is %d bytes, want %d", len(in.Sig), SigLen)
	case (in.KEL != nil) != (in.Notices != nil):
		return nil, nil, fail(ReasonBadInner, "key 11 (notice) goes exactly with key 10 (kel)")
	case strings.ContainsRune(in.From, 0):
		return nil, nil, fail(ReasonBadInner, "from contains U+0000")
	case strings.ContainsRune(in.To, 0):
		return nil, nil, fail(ReasonBadInner, "to contains U+0000")
	case strings.ContainsRune(in.IX, 0):
		return nil, nil, fail(ReasonBadInner, "ix contains U+0000")
	}
	if raw, ok := fields[keyRK]; ok {
		if in.RK, err = decodeRK(raw); err != nil {
			return nil, nil, failWrap(ReasonBadRK, err, "")
		}
	}
	if raw, ok := fields[keyGrant]; ok {
		in.Grant = append(cbor.RawMessage(nil), raw...)
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

// rawNotices decodes inner key 11: an array of exactly noticesPerMessage
// byte strings of at most MaxNoticeBytes each.
func rawNotices(raw cbor.RawMessage) ([][]byte, error) {
	if len(raw) == 0 || raw[0]>>5 != majorArray {
		return nil, fmt.Errorf("field %d is not an array", keyNotice)
	}
	var items []cbor.RawMessage
	if err := coredet.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("field %d: %w", keyNotice, err)
	}
	if len(items) != noticesPerMessage {
		return nil, fmt.Errorf("field %d has %d notices, want %d", keyNotice, len(items), noticesPerMessage)
	}
	out := make([][]byte, len(items))
	for i, it := range items {
		n, err := rawBytes(fieldMap{0: it}, 0)
		if err != nil {
			return nil, fmt.Errorf("field %d item %d: %w", keyNotice, i, err)
		}
		if len(n) > MaxNoticeBytes {
			return nil, fmt.Errorf("field %d item %d is %d bytes, cap %d", keyNotice, i, len(n), MaxNoticeBytes)
		}
		out[i] = n
	}
	return out, nil
}

// CheckTime is receive step 5: now <= exp, ts <= now + ClockSkewMS, and
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

// DefaultRotationGrace is the rotation grace of receive step 7.
const DefaultRotationGrace = time.Hour

// VerifyInnerSig is receive step 7. kel is the sender KEL resolved in step 6
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

// VerifyInnerKeys is receive step 8: decode the sender's key set carried in
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
