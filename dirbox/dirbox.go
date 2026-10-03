// Package dirbox seals and opens directory entries, so that a directory can be listed in full
// without telling anyone who is in it.
//
// Every entry of a hub's directory is a box only a party that already knows the agent's AID can
// open (labels L9 and L10 in docs/wire-keys.md):
//
//	h   = SHA-256("anet-dir-hash/v1" ‖ 0x00 ‖ UTF-8(aid))
//	K   = HKDF-SHA256(ikm = UTF-8(aid), salt = empty, info = "anet-dir-box/v1", L = 32)
//	box = nonce(12) ‖ ChaCha20-Poly1305(K, nonce, aad = h, pt = coredet(DirEntry))
//
// The hub files a box under h and answers queries by a prefix of h (a bucket), so a reader asks for
// many entries at once and opens the one whose AID it knows; the hub never learns which. The hash
// and the key carry different labels, so knowing h (which the hub publishes) gives nothing towards
// K. Anyone who knows the AID can open the box: the protection is against enumeration, not against
// someone who already has the AID.
//
// The package does no I/O and checks only what it can check alone: the box opens under the AID,
// the entry decodes strictly and names that AID. The KEL, key set, card and notice inside are
// opaque here; a reader verifies them before using the entry (an entry that fails is skipped).
package dirbox

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ANetResearch/ANetCore/coredet"
)

// Sizes, in bytes.
const (
	// HashLen is the length of h.
	HashLen = sha256.Size
	// KeyLen is the length of K.
	KeyLen = chacha20poly1305.KeySize
	// NonceLen is the length of the nonce that starts a box.
	NonceLen = chacha20poly1305.NonceSize
	// Overhead is how much longer a box is than its plaintext: the nonce and the AEAD tag.
	Overhead = NonceLen + chacha20poly1305.Overhead
	// MaxBoxLen is the largest box a directory carries (192 KiB). A hub leaves a larger entry out
	// of its directory; Seal refuses to make one and Open refuses to look into one.
	MaxBoxLen = 192 << 10
	// HashBits is the number of bits of h, the widest a bucket prefix can be.
	HashBits = HashLen * 8
)

// Domain-separation labels (L9, L10).
const (
	hashLabel = "anet-dir-hash/v1"
	boxLabel  = "anet-dir-box/v1"
)

// Errors. Use errors.Is: the returned errors wrap these with detail.
var (
	// ErrAID: the AID is empty, is not valid UTF-8, or holds U+0000 (with U+0000 two AIDs could
	// hash alike).
	ErrAID = errors.New("dirbox: not a usable AID")
	// ErrHash: h is not the hash of this AID; the box is not this AID's entry.
	ErrHash = errors.New("dirbox: the entry is filed under another hash")
	// ErrOpen: the box does not open under this AID. Either it belongs to another AID or it was
	// altered. A reader skips the entry.
	ErrOpen = errors.New("dirbox: the box does not open under this AID")
	// ErrEntry: the plaintext is not a valid DirEntry for this AID (an unknown or missing key, a
	// key of the wrong type, a non-canonical encoding, or another AID). A reader skips the entry.
	ErrEntry = errors.New("dirbox: not a valid directory entry")
	// ErrTooLarge: the box exceeds MaxBoxLen.
	ErrTooLarge = errors.New("dirbox: the entry is larger than a directory carries")
	// ErrPrefix: a bucket prefix is not ceil(bits/8) bytes with the bits past bits set to zero, or
	// bits is outside 0..HashBits.
	ErrPrefix = errors.New("dirbox: malformed bucket prefix")
)

// DirEntry is the plaintext of a directory box (DirEntry in docs/wire-keys.md). Every key
// outside 1..6 is refused; there is no extension range.
//
//anet:wire DirEntry
type DirEntry struct {
	// AID is the agent the entry describes. It must equal the AID the box is sealed under.
	AID string `cbor:"1,keyasint"`
	// Home is the AID of the agent's home hub.
	Home string `cbor:"2,keyasint"`
	// KEL is the agent's key event log, as the hub holds it.
	KEL []byte `cbor:"3,keyasint"`
	// Keys is the agent's signed encryption key set (SignedEncKeySet).
	Keys []byte `cbor:"4,keyasint"`
	// Card is the agent's A2A card bytes; absent when it has none.
	Card []byte `cbor:"5,keyasint,omitempty"`
	// Notice is the witness notice (NoticeWire) for the KEL's tip; absent when there is none.
	Notice []byte `cbor:"6,keyasint,omitempty"`
}

// checkAID refuses an AID that cannot be hashed unambiguously.
func checkAID(aid string) error {
	switch {
	case aid == "":
		return fmt.Errorf("%w: empty", ErrAID)
	case strings.IndexByte(aid, 0) >= 0:
		return fmt.Errorf("%w: it holds U+0000", ErrAID)
	case !utf8.ValidString(aid):
		return fmt.Errorf("%w: it is not valid UTF-8", ErrAID)
	}
	return nil
}

// check reports why e is not a DirEntry a directory may carry.
func (e *DirEntry) check() error {
	switch {
	case e == nil:
		return fmt.Errorf("%w: no entry", ErrEntry)
	case e.AID == "":
		return fmt.Errorf("%w: key 1 (aid) is missing", ErrEntry)
	case e.Home == "":
		return fmt.Errorf("%w: key 2 (home) is missing", ErrEntry)
	case len(e.KEL) == 0:
		return fmt.Errorf("%w: key 3 (kel) is missing", ErrEntry)
	case len(e.Keys) == 0:
		return fmt.Errorf("%w: key 4 (keys) is missing", ErrEntry)
	}
	if err := checkAID(e.AID); err != nil {
		return fmt.Errorf("%w: key 1 (aid): %v", ErrEntry, err)
	}
	if err := checkAID(e.Home); err != nil {
		return fmt.Errorf("%w: key 2 (home): %v", ErrEntry, err)
	}
	return nil
}

// Marshal returns the CoreDet encoding of e (the plaintext of its box). An entry missing a
// required key, or naming an unusable AID, is ErrEntry.
func (e *DirEntry) Marshal() ([]byte, error) {
	if err := e.check(); err != nil {
		return nil, err
	}
	b, err := coredet.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	return b, nil
}

// UnmarshalDirEntry decodes the plaintext of a box strictly: a CBOR map with keys 1..6 of the
// registered types and nothing else, keys 1..4 present, in canonical CoreDet encoding (decoding
// and re-encoding gives the same bytes). Anything else is ErrEntry.
func UnmarshalDirEntry(b []byte) (*DirEntry, error) {
	if len(b) == 0 || b[0]>>5 != 5 { // CBOR major type 5: map
		return nil, fmt.Errorf("%w: not a CBOR map", ErrEntry)
	}
	var e DirEntry
	if err := coredet.UnmarshalStrict(b, &e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	if err := e.check(); err != nil {
		return nil, err
	}
	again, err := coredet.Marshal(&e)
	if err != nil || !bytes.Equal(again, b) {
		// A null or empty value for an optional key, a non-shortest length, an indefinite
		// length: each decodes to the same entry, and only the canonical bytes are accepted.
		return nil, fmt.Errorf("%w: not the canonical encoding", ErrEntry)
	}
	return &e, nil
}

// Hash returns h, the 32-byte hash an AID's entry is filed under (L9).
func Hash(aid string) ([]byte, error) {
	if err := checkAID(aid); err != nil {
		return nil, err
	}
	d := sha256.New()
	d.Write([]byte(hashLabel))
	d.Write([]byte{0})
	d.Write([]byte(aid))
	return d.Sum(nil), nil
}

// Key returns K, the 32-byte key of an AID's box (L10).
func Key(aid string) ([]byte, error) {
	if err := checkAID(aid); err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, []byte(aid), nil, boxLabel, KeyLen)
}

// aeadFor returns the AEAD and h for aid.
func aeadFor(aid string) (h []byte, aead cipher.AEAD, err error) {
	if h, err = Hash(aid); err != nil {
		return nil, nil, err
	}
	k, err := Key(aid)
	if err != nil {
		return nil, nil, err
	}
	a, err := chacha20poly1305.New(k)
	if err != nil {
		return nil, nil, fmt.Errorf("dirbox: %w", err)
	}
	return h, a, nil
}

// Seal returns the box of entry e for the AID aid, which must be the AID the entry names. The
// 12-byte nonce is read from rand (crypto/rand when nil); a test passes a fixed reader to make the
// box reproducible. A box that would exceed MaxBoxLen is ErrTooLarge: the directory would not
// carry it.
func Seal(aid string, e *DirEntry, rand io.Reader) ([]byte, error) {
	if err := checkAID(aid); err != nil {
		return nil, err
	}
	pt, err := e.Marshal()
	if err != nil {
		return nil, err
	}
	if e.AID != aid {
		return nil, fmt.Errorf("%w: the entry names %q, not the AID it is sealed under", ErrEntry, e.AID)
	}
	if len(pt)+Overhead > MaxBoxLen {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrTooLarge, len(pt)+Overhead, MaxBoxLen)
	}
	h, a, err := aeadFor(aid)
	if err != nil {
		return nil, err
	}
	if rand == nil {
		rand = cryptoRand
	}
	box := make([]byte, NonceLen, len(pt)+Overhead)
	if _, err := io.ReadFull(rand, box); err != nil {
		return nil, fmt.Errorf("dirbox: nonce: %w", err)
	}
	return a.Seal(box, box[:NonceLen], pt, h), nil
}

// cryptoRand is the default nonce source.
var cryptoRand io.Reader = rand.Reader

// Open opens the box filed under h with the AID aid and returns the entry. h must be the AID's
// hash (ErrHash otherwise); a box that does not open is ErrOpen; a plaintext that is not a valid
// DirEntry naming aid is ErrEntry. Each of these means the same to a reader: skip the entry.
func Open(aid string, h, box []byte) (*DirEntry, error) {
	if len(box) > MaxBoxLen {
		return nil, fmt.Errorf("%w: %d bytes, the limit is %d", ErrTooLarge, len(box), MaxBoxLen)
	}
	want, a, err := aeadFor(aid)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(h, want) {
		return nil, ErrHash
	}
	if len(box) < Overhead {
		return nil, fmt.Errorf("%w: %d bytes is shorter than a box", ErrOpen, len(box))
	}
	pt, err := a.Open(nil, box[:NonceLen], box[NonceLen:], h)
	if err != nil {
		return nil, ErrOpen
	}
	e, err := UnmarshalDirEntry(pt)
	if err != nil {
		return nil, err
	}
	if e.AID != aid {
		return nil, fmt.Errorf("%w: the entry names %q, not the AID it opened under", ErrEntry, e.AID)
	}
	return e, nil
}

// Prefix returns the bucket prefix of h at bits bits: the first ceil(bits/8) bytes of h with the
// bits past bits set to zero. bits 0 is the whole directory (an empty prefix).
func Prefix(h []byte, bits int) ([]byte, error) {
	if len(h) != HashLen {
		return nil, fmt.Errorf("%w: h is %d bytes, want %d", ErrPrefix, len(h), HashLen)
	}
	if bits < 0 || bits > HashBits {
		return nil, fmt.Errorf("%w: %d bits is outside 0..%d", ErrPrefix, bits, HashBits)
	}
	n := (bits + 7) / 8
	p := bytes.Clone(h[:n])
	if r := bits % 8; r != 0 {
		p[n-1] &= byte(0xff << (8 - r))
	}
	return p, nil
}

// CheckPrefix reports whether prefix is a well-formed bucket prefix of bits bits: exactly
// ceil(bits/8) bytes, the bits past bits all zero, bits in 0..HashBits. A hub answers a malformed
// one 400 bad_request rather than guess which bucket was meant.
func CheckPrefix(prefix []byte, bits int) error {
	if bits < 0 || bits > HashBits {
		return fmt.Errorf("%w: %d bits is outside 0..%d", ErrPrefix, bits, HashBits)
	}
	n := (bits + 7) / 8
	if len(prefix) != n {
		return fmt.Errorf("%w: %d bytes for %d bits, want %d", ErrPrefix, len(prefix), bits, n)
	}
	if r := bits % 8; r != 0 && prefix[n-1]&byte(0xff>>r) != 0 {
		return fmt.Errorf("%w: bits past %d are set", ErrPrefix, bits)
	}
	return nil
}

// InBucket reports whether h falls in the bucket (prefix, bits). A malformed prefix holds nothing.
func InBucket(h, prefix []byte, bits int) bool {
	if CheckPrefix(prefix, bits) != nil {
		return false
	}
	p, err := Prefix(h, bits)
	return err == nil && bytes.Equal(p, prefix)
}
