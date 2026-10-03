package relayauth

// First-contact session (labels L7 and L8 in docs/wire-keys.md).
//
// A first-contact send must not name its sender to anyone but the recipient, yet the hub has to
// rate-limit it per sender. The daemon therefore opens a session with one signed request
// (ActionSession, body {epk}); the hub answers with a fresh random session id sid and session key
// k_sess, the key sealed to the one-time public key epk (SealSessionKey). Every send under the
// session then carries X-ANet-Session: sid and X-ANet-MAC: SessionMAC(k_sess, …). The hub can
// compute the same MAC, so the MAC proves nothing to a third party: it authenticates the request
// to the hub and to no one else.
//
// The key is sealed with HPKE (suite 1, base mode) although production runs over TLS: a plain-http
// test network would otherwise hand k_sess, and with it the right to send as that daemon, to
// anyone watching the session response.

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Lengths of the session values, in bytes.
const (
	// SessionIDLen is the length of a session id (sid): 16 random bytes chosen by the hub.
	SessionIDLen = 16
	// SessionKeyLen is the length of a session key (k_sess): 32 random bytes chosen by the hub.
	SessionKeyLen = 32
	// SessionMACLen is the length of a session MAC (HMAC-SHA256).
	SessionMACLen = sha256.Size
	// SessionPublicKeyLen is the length of the daemon's one-time public key epk (X25519).
	SessionPublicKeyLen = 32
	// sessionEncLen and sessionCTLen are the HPKE encapsulated key and the sealed k_sess (k_sess
	// plus the 16-byte ChaCha20-Poly1305 tag).
	sessionEncLen = 32
	sessionCTLen  = SessionKeyLen + 16
)

// Request header names of a session send. HTTP header names are case-insensitive; these are the
// canonical spellings a client sends. A session send also carries HeaderTS (the ts the MAC binds).
const (
	// HeaderSession carries the session id, encoded with EncodeSessionID.
	HeaderSession = "X-ANet-Session"
	// HeaderMAC carries the session MAC, encoded with EncodeMAC.
	HeaderMAC = "X-ANet-MAC"
	// HeaderHome carries the optional home-hub hint of a send. The session MAC covers it, so a
	// relay on the way cannot redirect a send by rewriting the hint.
	HeaderHome = "X-ANet-Home"
)

// Domain-separation labels (L7, L8).
const (
	sessionKeyLabel = "anet-sess-key/v1"
	sessionMACLabel = "anet-sess-mac/v1"
)

// Errors of the session functions. Use errors.Is: the returned errors wrap these with detail.
var (
	// ErrNUL: a text field that a session input separates with 0x00 (hub AID, method, request
	// target, X-ANet-Home) holds U+0000. With such a field two different requests could produce
	// the same input; the function refuses rather than compute anything. A hub answers the
	// request 400 bad_request.
	ErrNUL = errors.New("relayauth: a field holds U+0000")
	// ErrSessionInput: a session value has the wrong length, or the hub AID is empty.
	ErrSessionInput = errors.New("relayauth: malformed session input")
	// ErrSessionKey: the sealed session key does not open under this one-time key, hub AID and
	// session id. The daemon opens a new session.
	ErrSessionKey = errors.New("relayauth: the session key does not open")
	// ErrSessionMAC: the session MAC does not match the request. A hub answers 401
	// session_invalid.
	ErrSessionMAC = errors.New("relayauth: the session MAC does not match the request")
)

// sessionSuite is HPKE suite 1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
var (
	sessionKEM  = hpke.DHKEM(ecdh.X25519())
	sessionKDF  = hpke.HKDFSHA256()
	sessionAEAD = hpke.ChaCha20Poly1305()
)

// NewSessionKey returns a fresh one-time key pair for opening one session: esk stays with the
// daemon, epk (32 bytes) goes in the request body. A daemon makes a new pair for every session.
func NewSessionKey() (esk *ecdh.PrivateKey, epk []byte, err error) {
	esk, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return esk, esk.PublicKey().Bytes(), nil
}

// sessionKeyInfo is the HPKE info of L7:
//
//	"anet-sess-key/v1" ‖ 0x00 ‖ hubAID ‖ 0x00 ‖ sid
//
// It binds the sealed key to the hub that made it and to the session id it came with, so a key
// sealed for one session or one hub does not open as another's.
func sessionKeyInfo(hubAID string, sid []byte) ([]byte, error) {
	if hubAID == "" {
		return nil, fmt.Errorf("%w: empty hub AID", ErrSessionInput)
	}
	if strings.IndexByte(hubAID, 0) >= 0 {
		return nil, fmt.Errorf("%w: hub AID", ErrNUL)
	}
	if len(sid) != SessionIDLen {
		return nil, fmt.Errorf("%w: session id is %d bytes, want %d", ErrSessionInput, len(sid), SessionIDLen)
	}
	info := make([]byte, 0, len(sessionKeyLabel)+2+len(hubAID)+SessionIDLen)
	info = append(info, sessionKeyLabel...)
	info = append(info, 0)
	info = append(info, hubAID...)
	info = append(info, 0)
	return append(info, sid...), nil
}

// SealSessionKey seals the session key k for the daemon that sent epk (the hub's side of L7):
// HPKE base mode, suite 1, recipient key epk, info sessionKeyInfo(hubAID, sid), empty aad. hubAID
// is the AID of the hub making the session. It returns the encapsulated key enc (32 bytes) and the
// ciphertext ct (48 bytes), the {enc, ct} of the session response.
//
// An epk that is not a usable X25519 public key (wrong length, or a low-order point whose shared
// secret is zero) is an error: the hub answers 400 bad_request.
func SealSessionKey(epk []byte, hubAID string, sid, k []byte) (enc, ct []byte, err error) {
	if len(epk) != SessionPublicKeyLen {
		return nil, nil, fmt.Errorf("%w: epk is %d bytes, want %d", ErrSessionInput, len(epk), SessionPublicKeyLen)
	}
	if len(k) != SessionKeyLen {
		return nil, nil, fmt.Errorf("%w: session key is %d bytes, want %d", ErrSessionInput, len(k), SessionKeyLen)
	}
	info, err := sessionKeyInfo(hubAID, sid)
	if err != nil {
		return nil, nil, err
	}
	pk, err := sessionKEM.NewPublicKey(epk)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: epk: %v", ErrSessionInput, err)
	}
	enc, sender, err := hpke.NewSender(pk, sessionKDF, sessionAEAD, info)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: epk: %v", ErrSessionInput, err)
	}
	ct, err = sender.Seal(nil, k)
	if err != nil {
		return nil, nil, fmt.Errorf("relayauth: seal session key: %w", err)
	}
	return enc, ct, nil
}

// OpenSessionKey opens the session key the hub hubAID sealed for esk under session id sid (the
// daemon's side of L7). It returns k_sess (32 bytes). A response that does not open is
// ErrSessionKey: it was not made for this key, this hub or this session.
func OpenSessionKey(esk *ecdh.PrivateKey, hubAID string, sid, enc, ct []byte) ([]byte, error) {
	if esk == nil || esk.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("%w: the one-time key is not an X25519 key", ErrSessionInput)
	}
	info, err := sessionKeyInfo(hubAID, sid)
	if err != nil {
		return nil, err
	}
	if len(enc) != sessionEncLen || len(ct) != sessionCTLen {
		return nil, fmt.Errorf("%w: enc is %d bytes and ct %d, want %d and %d",
			ErrSessionKey, len(enc), len(ct), sessionEncLen, sessionCTLen)
	}
	sk, err := hpke.NewDHKEMPrivateKey(esk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionInput, err)
	}
	r, err := hpke.NewRecipient(enc, sk, sessionKDF, sessionAEAD, info)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionKey, err)
	}
	k, err := r.Open(nil, ct)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionKey, err)
	}
	if len(k) != SessionKeyLen {
		return nil, fmt.Errorf("%w: the key is %d bytes", ErrSessionKey, len(k))
	}
	return k, nil
}

// sessionMACInput is the HMAC message of L8:
//
//	"anet-sess-mac/v1" ‖ 0x00 ‖ sid ‖ 0x00 ‖ decimal(ts) ‖ 0x00 ‖ method ‖ 0x00 ‖ pathAndQuery ‖
//	0x00 ‖ home ‖ 0x00 ‖ SHA-256(body)
//
// sid (16 bytes) and the body digest (32 bytes) are fixed-length; the text fields are 0x00
// separated, which is unambiguous only while none of them holds 0x00 (ErrNUL).
func sessionMACInput(sid []byte, ts uint64, method, pathAndQuery, home string, body []byte) ([]byte, error) {
	if len(sid) != SessionIDLen {
		return nil, fmt.Errorf("%w: session id is %d bytes, want %d", ErrSessionInput, len(sid), SessionIDLen)
	}
	for _, f := range [...]struct{ name, v string }{
		{"method", method}, {"request target", pathAndQuery}, {HeaderHome, home},
	} {
		if strings.IndexByte(f.v, 0) >= 0 {
			return nil, fmt.Errorf("%w: %s", ErrNUL, f.name)
		}
	}
	digest := sha256.Sum256(body)
	tsText := strconv.FormatUint(ts, 10)
	in := make([]byte, 0, len(sessionMACLabel)+6+SessionIDLen+len(tsText)+len(method)+len(pathAndQuery)+len(home)+len(digest))
	in = append(in, sessionMACLabel...)
	in = append(in, 0)
	in = append(in, sid...)
	in = append(in, 0)
	in = append(in, tsText...)
	in = append(in, 0)
	in = append(in, method...)
	in = append(in, 0)
	in = append(in, pathAndQuery...)
	in = append(in, 0)
	in = append(in, home...)
	in = append(in, 0)
	return append(in, digest[:]...), nil
}

// SessionMAC returns the MAC of one session send (L8): HMAC-SHA256 under the session key k over
// the session id, the X-ANet-TS value ts, the HTTP method, the request target as sent (path and
// query, origin form), the X-ANet-Home value (empty when the header is absent) and the SHA-256 of
// the body. Changing any of them, the body included, gives another MAC.
func SessionMAC(k, sid []byte, ts uint64, method, pathAndQuery, home string, body []byte) ([]byte, error) {
	if len(k) != SessionKeyLen {
		return nil, fmt.Errorf("%w: session key is %d bytes, want %d", ErrSessionInput, len(k), SessionKeyLen)
	}
	in, err := sessionMACInput(sid, ts, method, pathAndQuery, home, body)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, k)
	m.Write(in)
	return m.Sum(nil), nil
}

// VerifySessionMAC checks mac against the request: nil when it is SessionMAC of the same inputs,
// ErrSessionMAC when it is not. The comparison is constant-time (hmac.Equal), so the time a hub
// takes to refuse does not tell a forger how many leading bytes were right. Input errors (ErrNUL,
// ErrSessionInput) are returned before any comparison.
func VerifySessionMAC(k, sid []byte, ts uint64, method, pathAndQuery, home string, body, mac []byte) error {
	want, err := SessionMAC(k, sid, ts, method, pathAndQuery, home, body)
	if err != nil {
		return err
	}
	if !hmac.Equal(want, mac) {
		return ErrSessionMAC
	}
	return nil
}

// Header value encodings: unpadded, strict base64url of an exact length (as for X-ANet-Sig). The
// encoding/base64 decoder skips CR and LF even in strict mode, so the decoders also require the
// exact encoded length; one value then has one accepted spelling.
var (
	sessionIDEncodedLen  = sigEncoding.EncodedLen(SessionIDLen)
	sessionMACEncodedLen = sigEncoding.EncodedLen(SessionMACLen)
)

// ErrBadSessionHeader is returned by DecodeSessionID and DecodeMAC for a header value that is not
// exactly one strictly encoded value of the right length.
var ErrBadSessionHeader = errors.New("relayauth: X-ANet-Session or X-ANet-MAC is not an unpadded base64url value of the right length")

// EncodeSessionID encodes a session id for HeaderSession (22 characters).
func EncodeSessionID(sid []byte) string { return sigEncoding.EncodeToString(sid) }

// DecodeSessionID decodes a HeaderSession value: exactly 22 characters of unpadded, strict
// base64url holding 16 bytes; anything else is ErrBadSessionHeader.
func DecodeSessionID(s string) ([]byte, error) {
	return decodeExact(s, sessionIDEncodedLen, SessionIDLen)
}

// EncodeMAC encodes a session MAC for HeaderMAC (43 characters).
func EncodeMAC(mac []byte) string { return sigEncoding.EncodeToString(mac) }

// DecodeMAC decodes a HeaderMAC value: exactly 43 characters of unpadded, strict base64url
// holding 32 bytes; anything else is ErrBadSessionHeader.
func DecodeMAC(s string) ([]byte, error) {
	return decodeExact(s, sessionMACEncodedLen, SessionMACLen)
}

func decodeExact(s string, encodedLen, n int) ([]byte, error) {
	if len(s) != encodedLen {
		return nil, ErrBadSessionHeader
	}
	b, err := sigEncoding.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, ErrBadSessionHeader
	}
	return b, nil
}
