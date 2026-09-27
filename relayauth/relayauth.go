// Package relayauth defines the canonical challenge a client signs to authenticate a Hub request.
// The client signs the preimage with its KEL current key; the Hub rebuilds the identical bytes and
// verifies them against the registered KEL (identity.VerifyObject), bounded by MaxSkewMillis so a
// captured signature cannot be replayed indefinitely. Shared here so the signer (daemon) and
// verifier (hub) can never disagree on the preimage.
//
// Two versions exist. v1 (Preimage) signs only action, AID and time, and travels in JSON request
// bodies. v2 (PreimageV2, A2A-DESIGN §3.7) additionally binds the hub's AID and a hash of the HTTP
// method, request target and body, and travels in the X-ANet-* request headers. v1 remains for the
// wire-1 hub and daemon until both move to wire 2.
package relayauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
)

// Auth actions (part of the signed preimage so a signature for one action cannot be reused for
// another). Every action is a lowercase ASCII word without "/", because "/" separates the preimage
// fields.
const (
	ActionPoll = "poll"
	ActionAck  = "ack"
	// ActionRegister authenticates a registry publish (proves the registrant holds the AID's key, so a
	// public KEL cannot be replayed by a stranger to overwrite someone's registration).
	ActionRegister = "register"
	// ActionProfile authenticates a self-description update (summary/readme/pricing) for an AID.
	ActionProfile = "profile"

	// The actions below are introduced by relay v2 (A2A-DESIGN §3.7).

	// ActionSend authenticates POST /relay/send. The hub uses the sender only for rate limiting and
	// quota and does not store it.
	ActionSend = "send"
	// ActionVisibility authenticates POST /agents/{aid}/visibility (directory visibility change).
	ActionVisibility = "visibility"
	// ActionDeregister authenticates POST /agents/{aid}/deregister.
	ActionDeregister = "deregister"
	// ActionP2P authenticates POST /agents/{aid}/p2p (publishing the AID's p2p rendezvous addresses).
	ActionP2P = "p2p"
	// ActionBalance authenticates GET /agents/{aid}/balance, which returns details only to the AID itself.
	ActionBalance = "balance"
	// ActionLedger authenticates GET /agents/{aid}/ledger, which returns details only to the AID itself.
	ActionLedger = "ledger"
	// ActionRedemptions authenticates GET /agents/{aid}/redemptions, which returns details only to the
	// AID itself.
	ActionRedemptions = "redemptions"
	// ActionKeys authenticates publishing the AID's EncKeySet (POST /agents/{aid}/keys).
	ActionKeys = "keys"
)

// MaxSkewMillis bounds the accepted clock skew / replay window for a signed relay auth challenge.
const MaxSkewMillis = 5 * 60 * 1000

// Request header names carrying relay v2 authentication (A2A-DESIGN §3.7). HTTP header names are
// case-insensitive; these are the canonical spellings a client sends.
const (
	// HeaderAID carries the signer's AID.
	HeaderAID = "X-ANet-AID"
	// HeaderTS carries the signing time in unix milliseconds, decimal ASCII.
	HeaderTS = "X-ANet-TS"
	// HeaderSeq carries the key_state_seq the signature was made under, decimal ASCII.
	HeaderSeq = "X-ANet-Seq"
	// HeaderSig carries the Ed25519 signature over PreimageV2, encoded with EncodeSig.
	HeaderSig = "X-ANet-Sig"
)

// Preimage returns the exact bytes a caller signs to authenticate a relay mailbox operation for aid at
// ts (unix millis).
//
// Deprecated: v1 does not bind the hub, the HTTP method, the request target or the body, so a
// signature captured on one request is valid for any other request with the same action within the
// skew window, on any hub. Wire-2 clients and hubs use PreimageV2. Kept so wire-1 code builds until
// it is removed.
func Preimage(action, aid string, ts uint64) []byte {
	return []byte("anet-relay/" + action + "/" + aid + "/" + strconv.FormatUint(ts, 10))
}

// PreimageV2 returns the exact bytes a caller signs to authenticate one relay v2 HTTP request
// (A2A-DESIGN §3.7):
//
//	"anet-relay/v2/" + action + "/" + aid + "/" + hubAID + "/" + decimal(ts) + "/" +
//	base64url(SHA-256(method ‖ 0x00 ‖ pathAndQuery ‖ 0x00 ‖ body))
//
// The digest is encoded with the URL-safe base64 alphabet of RFC 4648 §5 WITHOUT "=" padding
// (base64.RawURLEncoding), so it is always 43 characters. Unpadded was chosen because the digest
// length is fixed and padding would add a character with no information that two implementations
// could disagree on.
//
// Fields and their preconditions:
//   - action is one of the Action* constants; aid and hubAID are CIDs. None contains "/", which is
//     what keeps the "/"-separated prefix unambiguous. The digest alphabet ("A–Z a–z 0–9 - _") has
//     no "/" either.
//   - hubAID is the AID of the hub the request is addressed to, so a signature captured by one hub
//     cannot be presented to another.
//   - method is the HTTP method token (for example "POST"), case-sensitive as sent.
//   - pathAndQuery is the origin-form request target exactly as the client sent it: the escaped
//     path, followed by "?" and the raw query when a query is present. Scheme and host are not
//     included; a proxy that rewrites the path breaks verification.
//   - body is the raw request body bytes, empty for a request without a body. The hub hashes the
//     bytes it read (within its size limit) before decoding them.
//
// The 0x00 separators inside the digest input keep method, target and body apart: an HTTP method
// token and an origin-form target cannot contain a NUL byte.
func PreimageV2(action, aid, hubAID string, ts uint64, method, pathAndQuery string, body []byte) []byte {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(pathAndQuery))
	h.Write([]byte{0})
	h.Write(body)
	digest := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return []byte("anet-relay/v2/" + action + "/" + aid + "/" + hubAID + "/" +
		strconv.FormatUint(ts, 10) + "/" + digest)
}

// sigEncoding is the HeaderSig value encoding: URL-safe base64 without padding, strict (non-zero
// trailing bits rejected). Strict mode alone does not make the spelling unique, because the
// encoding/base64 decoder skips CR and LF anywhere in its input; DecodeSig therefore also requires
// the exact encoded length.
var sigEncoding = base64.RawURLEncoding.Strict()

// sigEncodedLen is the length of an encoded Ed25519 signature: 86 characters.
var sigEncodedLen = sigEncoding.EncodedLen(ed25519.SignatureSize)

// ErrBadSig is returned by DecodeSig for a header value that is not exactly one strictly encoded
// 64-byte signature.
var ErrBadSig = errors.New("relayauth: X-ANet-Sig is not an unpadded base64url 64-byte signature")

// EncodeSig encodes a signature for the HeaderSig header (base64url, no padding; 86 characters for
// an Ed25519 signature).
func EncodeSig(sig []byte) string { return sigEncoding.EncodeToString(sig) }

// DecodeSig decodes a HeaderSig value. It accepts only the unpadded, strict base64url form of a
// 64-byte signature, exactly 86 characters; a padded value, a value containing CR or LF, or any
// other length is ErrBadSig. One signature therefore has one accepted spelling, which matters to a
// hub that keys its replay cache on the header value rather than on the decoded bytes.
func DecodeSig(s string) ([]byte, error) {
	if len(s) != sigEncodedLen {
		return nil, ErrBadSig
	}
	b, err := sigEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.SignatureSize {
		return nil, ErrBadSig
	}
	return b, nil
}
