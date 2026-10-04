package seal

import (
	"bytes"
	"crypto/hpke"
	"errors"
	"fmt"
	"strings"

	"github.com/ANetResearch/ANetCore/coredet"
)

// The second layer (FS §2.5, core §2.2 and §3.2 L2).
//
// Each side of an interaction holds one interaction key for it: the requester's E_r and the
// provider's E_p. A side announces the public half in inner key 15 (rk) of every message it
// seals while it still holds the key (FS-X4), and seals its own messages with a second layer
// to the public half the peer announced (FS-X5). The second layer sits inside the Wrap: the
// layer-1 plaintext carries its ikid, enc2 and ciphertext instead of the inner. When a side
// ends its part of the interaction it deletes the private half, and from then on nothing
// sealed to it in that interaction opens, whatever happens to the epoch keys
// (sealed-to-closed-interaction).

// IXLabel is the value of layer-2 HPKE info key 1 (core §3.2 L2).
const IXLabel = "anet-ix/v2"

// RK is an interaction public key (inner key 15, core §2.3): the key the
// sender wants the second layer of later messages in the interaction sealed
// to (FS §2.6). In 0.3.0 Suite is 1 and Pub 32 bytes.
//
//anet:wire RK
type RK struct {
	Suite Suite  `cbor:"1,keyasint"`
	Pub   []byte `cbor:"2,keyasint"`
}

// KID is the key id of r (L15), the ikid of a second layer sealed to it.
func (r *RK) KID() []byte { return KID(r.Suite, r.Pub) }

// check is the rule of FS-C11: suite 1 and a public key of its length.
func (r *RK) check() error {
	if r.Suite != SuiteX25519 {
		return fmt.Errorf("rk suite %d, want %d", r.Suite, SuiteX25519)
	}
	if len(r.Pub) != params(r.Suite).pubLen {
		return fmt.Errorf("rk pub is %d bytes, want %d", len(r.Pub), params(r.Suite).pubLen)
	}
	return nil
}

// decodeRK decodes inner key 15 (FS-C11): exactly {1: suite, 2: pub}, suite 1
// and a 32-byte pub.
func decodeRK(raw []byte) (*RK, error) {
	m, err := decodeFields(raw)
	if err != nil {
		return nil, fmt.Errorf("rk: %w", err)
	}
	for k := range m {
		if k < 1 || k > 2 {
			return nil, fmt.Errorf("rk has key %d", k)
		}
	}
	suite, err := rawUint(m, 1)
	if err != nil {
		return nil, fmt.Errorf("rk suite: %w", err)
	}
	if suite > 0xff {
		return nil, fmt.Errorf("rk suite %d", suite)
	}
	r := &RK{Suite: Suite(suite)}
	if r.Pub, err = rawBytes(m, 2); err != nil {
		return nil, fmt.Errorf("rk pub: %w", err)
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return r, nil
}

// IXKey is one of this node's interaction keys (FS §2.8): the private half of
// an rk it announced in interaction IX with PeerAID. Private is the RFC 9180
// SerializePrivateKey output and is secret; the holder deletes it when its
// part of the interaction ends (FS §4.5.4).
type IXKey struct {
	IX, PeerAID  string
	Suite        Suite
	Pub, Private []byte
}

// IXKeyLookup finds this node's interaction key by ikid. It returns (nil,
// nil) when there is none (the interaction is closed for this node) and a
// non-nil error when the store cannot be read; Open passes that error through
// so the caller retries rather than drops (ENG-V8).
type IXKeyLookup interface {
	IXKey(ikid []byte) (*IXKey, error)
}

// GenerateIXKey creates this node's interaction key for interaction ix with
// peerAID (FS-X1, FS-X2). The caller stores it with the interaction, in the
// same transaction, and announces k.RK() in every message it seals in the
// interaction while it holds the key.
//
// ix and peerAID are what Open later requires of a message sealed to the key
// (ikey-mismatch), so both must be non-empty and free of U+0000, the values an
// inner can carry (CORE-E9).
func GenerateIXKey(suite Suite, ix, peerAID string) (*IXKey, error) {
	p := params(suite)
	if p == nil {
		return nil, fail(ReasonUnknownSuite, "suite %d", suite)
	}
	switch {
	case ix == "" || peerAID == "":
		return nil, fail(ReasonInvalidInput, "an interaction key needs its interaction and its peer")
	case strings.ContainsRune(ix, 0) || strings.ContainsRune(peerAID, 0):
		return nil, fail(ReasonInvalidInput, "ix and peer may not contain U+0000")
	}
	sk, err := p.kem.GenerateKey()
	if err != nil {
		return nil, failWrap(ReasonInternalError, err, "generate interaction key")
	}
	priv, err := sk.Bytes()
	if err != nil {
		return nil, failWrap(ReasonInternalError, err, "serialize interaction key")
	}
	return &IXKey{IX: ix, PeerAID: peerAID, Suite: suite, Pub: sk.PublicKey().Bytes(), Private: priv}, nil
}

// RK returns the public half of k as inner key 15 carries it.
func (k *IXKey) RK() *RK { return &RK{Suite: k.Suite, Pub: append([]byte(nil), k.Pub...)} }

// KID returns the key id of k (L15): the ikid of a second layer sealed to it.
func (k *IXKey) KID() []byte { return KID(k.Suite, k.Pub) }

// answers reports why k cannot be the key of ikid, or nil when it can: a suite
// this build implements, a public key of the suite's length, and ikid ==
// KID(suite, pub). A lookup that returns another key than the one asked for
// is treated as holding none (sealed-to-closed-interaction), as Open treats
// a key ring that returns another kid.
func (k *IXKey) answers(ikid []byte) error {
	p := params(k.Suite)
	switch {
	case p == nil:
		return fmt.Errorf("interaction key suite %d", k.Suite)
	case len(k.Pub) != p.pubLen:
		return fmt.Errorf("interaction key pub is %d bytes, want %d", len(k.Pub), p.pubLen)
	case !bytes.Equal(k.KID(), ikid):
		return errors.New("the lookup returned the key of another ikid")
	}
	return nil
}

// layer2Sender is the second layer's HPKE sender context of one Seal call.
type layer2Sender struct {
	ikid, enc2 []byte
	sender     *hpke.Sender
}

// newLayer2Sender checks the peer's interaction key (FS-C10, FS-C11) and sets
// up the layer-2 sender context to it for recipient to. Every failure is
// invalid-input: the key is the caller's, from a message it accepted.
func newLayer2Sender(to string, rk *RK) (*layer2Sender, error) {
	if err := rk.check(); err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "peer rk")
	}
	p := params(rk.Suite)
	if p == nil {
		return nil, fail(ReasonInvalidInput, "peer rk suite %d", rk.Suite)
	}
	pk, err := p.kem.NewPublicKey(rk.Pub)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "peer rk")
	}
	ikid := rk.KID()
	info, err := IXInfo(to, rk.Suite, ikid)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "layer-2 hpke info")
	}
	// A public key of small order (an all-zero shared secret) fails here.
	enc2, sender, err := hpke.NewSender(pk, p.kdf, p.aead, info)
	if err != nil {
		return nil, failWrap(ReasonInvalidInput, err, "peer rk: hpke sender")
	}
	return &layer2Sender{ikid: ikid, enc2: enc2, sender: sender}, nil
}

// openLayer2 opens the second layer of a Wrap with key, the interaction key
// its ikid names, for recipient to, and returns the inner it carries. A key
// that does not load or a ciphertext that does not open is decrypt-failed.
func openLayer2(to string, key *IXKey, w *wrapFields) ([]byte, error) {
	p := params(key.Suite)
	sk, err := p.kem.NewPrivateKey(key.Private)
	if err != nil {
		return nil, failWrap(ReasonDecrypt, err, "interaction key private key")
	}
	info, err := IXInfo(to, key.Suite, w.ikid)
	if err != nil {
		// Not reachable: to passed ParseOuter and ikid decodeWrap.
		return nil, failWrap(ReasonDecrypt, err, "layer-2 hpke info")
	}
	r, err := hpke.NewRecipient(w.enc2, sk, p.kdf, p.aead, info)
	if err != nil {
		return nil, failWrap(ReasonDecrypt, err, "layer-2 hpke recipient")
	}
	pt, err := r.Open(nil, w.body)
	if err != nil {
		return nil, failWrap(ReasonDecrypt, err, "second layer open")
	}
	return pt, nil
}

// IXInfo returns the layer-2 HPKE info (L2): coredet({1: "anet-ix/v2", 2: to,
// 3: suite, 4: ikid}), where to is the recipient AID (the outer to) and ikid
// the kid of the recipient's interaction key. aad is empty.
func IXInfo(to string, suite Suite, ikid []byte) ([]byte, error) {
	return coredet.Marshal(hpkeInfo{IXLabel, to, suite, ikid})
}
