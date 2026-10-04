// Package relayauth defines what a client signs or MACs to authenticate a hub request.
//
// A signed request (PreimageV2) binds the action, the signer's AID, the hub's AID, the time and a
// hash of the HTTP method, request target and body, and travels in the X-ANet-* request headers.
// The client signs it with its KEL current key; the hub rebuilds the identical bytes and verifies
// them against the registered KEL, bounded by MaxSkewMillis so a captured signature cannot be
// replayed indefinitely. Agents and peer hubs sign the same way (label L22 in docs/wire-keys.md).
//
// A first-contact send carries no signature: the daemon opens a session with one signed request
// (ActionSession), the hub hands it a session key sealed to a one-time key (SealSessionKey,
// OpenSessionKey), and each send then carries a MAC under that key (SessionMAC,
// VerifySessionMAC). See session.go.
//
// Shared here so the signer (daemon) and verifier (hub) can never disagree on the bytes. The
// wire-1 challenge (action, AID and time only) and the actions "send" and "p2p" are retired in
// 0.3.0: a captured wire-1 signature authorised any request with the same action on any hub.
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
// fields. The set is the "relayauth actions" table of docs/wire-keys.md; ValidAction reports
// membership. A retired action ("send", "p2p", "fedkeys") has no constant and is never assigned
// again.
const (
	ActionPoll = "poll"
	ActionAck  = "ack"
	// ActionRegister authenticates a registry publish (proves the registrant holds the AID's key, so a
	// public KEL cannot be replayed by a stranger to overwrite someone's registration).
	ActionRegister = "register"
	// ActionProfile authenticates a self-description update (summary/readme) for an AID.
	ActionProfile = "profile"
	// ActionVisibility authenticates a directory visibility change.
	ActionVisibility = "visibility"
	// ActionDeregister authenticates a deregistration.
	ActionDeregister = "deregister"
	// ActionBalance authenticates GET /agents/{aid}/balance, which returns details only to the AID itself.
	ActionBalance = "balance"
	// ActionLedger authenticates GET /agents/{aid}/ledger, which returns details only to the AID itself.
	ActionLedger = "ledger"
	// ActionRedemptions authenticates GET /agents/{aid}/redemptions, which returns details only to the
	// AID itself.
	ActionRedemptions = "redemptions"
	// ActionKeys authenticates publishing the AID's EncKeySet (POST /agents/{aid}/keys).
	ActionKeys = "keys"

	// ActionSession authenticates POST /relay/session: the daemon opens a first-contact session
	// with its own hub. The sends made under the session carry a session MAC, not a signature.
	ActionSession = "session"
	// ActionRevoke authenticates POST /mailbox/revoke: the owner revokes capabilities it issued.
	ActionRevoke = "revoke"
	// ActionReview authenticates POST /reviews: the reviewer uploads a review (evidence v2) with the
	// salt that proves it is the requester the receipt committed to.
	ActionReview = "review"
	// ActionLiabProof authenticates GET /agents/{aid}/liability-proof, which answers only the AID
	// itself: its balance leaf and the path to the published supply epoch root.
	ActionLiabProof = "liab_proof"

	// The actions below are signed by a peer hub with its own identity: every /fed/v3 route is
	// authenticated like an agent request, under the peer hub's KEL.

	// ActionFedForward authenticates POST /fed/v3/forward (a peer hub hands on one envelope).
	ActionFedForward = "fed_forward"
	// ActionFedBucket authenticates POST /fed/v3/directory:bucket (a peer hub asks for one bucket).
	ActionFedBucket = "fed_bucket"
	// ActionFedCards authenticates GET /fed/v3/cards (a peer hub syncs the directory's cards).
	ActionFedCards = "fed_cards"
	// ActionFedSettle authenticates POST /fed/v3/settle: the payee's hub forwards a settlement to
	// the hub that holds the payer's balance.
	ActionFedSettle = "fed_settle"
	// ActionFedReviews authenticates GET /fed/v3/reviews (a peer hub syncs stored reviews).
	ActionFedReviews = "fed_reviews"
	// ActionFedClear authenticates POST /fed/v3/clear (a peer hub clears what one hub owes the
	// other).
	ActionFedClear = "fed_clear"
)

// validActions holds every Action* constant of this package. A new constant goes here too
// (TestEveryActionConstantIsValid reads the source to make sure it does).
var validActions = map[string]bool{
	ActionPoll: true, ActionAck: true, ActionRegister: true, ActionProfile: true,
	ActionVisibility: true, ActionDeregister: true, ActionBalance: true, ActionLedger: true,
	ActionRedemptions: true, ActionKeys: true,
	ActionSession: true, ActionRevoke: true, ActionReview: true, ActionLiabProof: true,
	ActionFedForward: true, ActionFedBucket: true, ActionFedCards: true,
	ActionFedSettle: true, ActionFedReviews: true, ActionFedClear: true,
}

// ValidAction reports whether action is a relayauth action of this wire version. A retired action
// ("send", "p2p", "fedkeys") or a name never assigned is not: nothing may sign or accept it, and a
// hub answers a request signed for one with 401 unauthorized.
func ValidAction(action string) bool { return validActions[action] }

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
