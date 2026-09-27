package seal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
)

// Suite identifies an HPKE ciphersuite (§3.2). It is a uint8 because the kid
// derivation hashes it as a single byte (§3.1); a wire value above 255 fails
// to decode rather than being truncated into a collision.
type Suite uint8

const (
	// SuiteX25519 is suite 1: DHKEM(X25519, HKDF-SHA256) 0x0020,
	// HKDF-SHA256 0x0001, ChaCha20-Poly1305 0x0003. The only suite this
	// version implements.
	SuiteX25519 Suite = 1
	// SuiteXWing is suite 2: MLKEM768-X25519 0x647a with HKDF-SHA256 and
	// ChaCha20-Poly1305. The number is reserved (§3.2) and not implemented:
	// an envelope that names it is rejected as ReasonUnknownSuite, and a key
	// set may list such keys but SelectKey never picks them.
	SuiteXWing Suite = 2
)

// suiteParams is the HPKE instantiation of one implemented suite.
type suiteParams struct {
	kem    hpke.KEM
	kdf    hpke.KDF
	aead   hpke.AEAD
	pubLen int // serialized public key length
	encLen int // encapsulated key length (Nenc)
}

var suite1 = &suiteParams{
	kem:    hpke.DHKEM(ecdh.X25519()),
	kdf:    hpke.HKDFSHA256(),
	aead:   hpke.ChaCha20Poly1305(),
	pubLen: 32,
	encLen: 32,
}

// params returns the HPKE instantiation for s, or nil when this build does
// not implement s.
func params(s Suite) *suiteParams {
	if s == SuiteX25519 {
		return suite1
	}
	return nil
}

// Supported reports whether this build can seal to and open under s.
func Supported(s Suite) bool { return params(s) != nil }

// KIDLen is the length of a key id.
const KIDLen = 16

// kidLabel is the domain separation prefix of the kid hash (§3.1).
const kidLabel = "anet-enc-kid/v1"

// KID returns SHA-256("anet-enc-kid/v1" || u8(suite) || pub)[:16] (§3.1).
//
// The suite is inside the hash so that the same public bytes listed under two
// suites get two different ids; a recipient then never tries a key under a
// suite it was not published for.
func KID(suite Suite, pub []byte) []byte {
	h := sha256.New()
	h.Write([]byte(kidLabel))
	h.Write([]byte{byte(suite)})
	h.Write(pub)
	return h.Sum(nil)[:KIDLen]
}
