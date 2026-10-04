package identity

// Recovery seed and recovery file (KEL §2.3, §2.4, C-30–C-37; core §2.6 RecoveryBlob, L19, L20).
//
// The next key of an identity is never kept in its data directory. Every next key is derived
// from a 32-byte recovery seed RS that only the anet CLI, or anet-hub, ever holds (L19):
//
//	seed(aid, seq)        = HKDF-SHA256(ikm = RS, salt = "anet-kel-next/v1", info = UTF-8(aid) ‖ 0x00 ‖ u64be(seq), L = 32)
//	key(aid, seq)         = the Ed25519 key of seed(aid, seq)
//	next_digest(aid, seq) = SHA-256(public key of key(aid, seq)), the same digest as KeyEvent key 6
//
// The rot or dip at seq j reveals key(aid, j) (RecoverySeed) and a rot at seq j commits to
// next_digest(aid, j+1) (NextDigest).
//
// RS is kept in a recovery file, a short UTF-8 text whose only authoritative part is a base64
// block holding coredet(RecoveryBlob):
//
//	anet-recovery v1
//	AID <aid>
//	hub <witness hub URL when the file was written>     (a hint; absent when there is none)
//	commits <seq> <next_digest in lower-case hex>       (what this RS committed to; public)
//	<blank line>
//	<base64 of coredet(RecoveryBlob), 64 characters a line>
//	<blank line>                                        (WithRecoveryNote adds these three lines:
//	<note, Chinese>                                      the sentence the CLI's reason table holds
//	<note, English>                                      for the file; a reader ignores them)
//
// The block seals RS with XChaCha20-Poly1305 under one of two keys, which key 2 (kdf) names (L20):
//
//   - argon2id: argon2id(NFC(passphrase), salt, t = 3, m = 64 MiB, p = 4, 32). The normal file,
//     kept outside the data directory (SealRecoveryFile, OpenRecoveryFile).
//   - local: the 32 bytes of recovery_local.key in the data directory. The file of an identity that
//     joined its hub without a terminal, until `anet identity protect` replaces it (C-36;
//     SealRecoveryFileLocal, OpenRecoveryFileLocal).
//
// The aad is coredet of the blob without key 7, so the AID, kdf, hub and commits are all bound to
// the ciphertext: a local block cannot be passed off as a passphrase block or the other way round.
// The text header repeats the AID, hub and commits for people; a header that disagrees with the
// block is refused (ErrRecoveryWrongIdentity).
//
// Nothing here does I/O. Writing the file (temporary file, fsync, rename), its mode and its path
// are the callers'. OpenRecoveryFile and RecoverySeed are for ANet's cmd/anet and ANetHub's
// cmd/anet-hub only, and the two *Local functions for cmd/anet only: the daemon never holds a
// recovery seed (SI-38; TestRecoveryAPIScope).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/text/unicode/norm"

	"github.com/ANetResearch/ANetCore/coredet"
)

// MinPassphraseRunes is the shortest recovery passphrase, in Unicode code points after NFC (C-34).
const MinPassphraseRunes = 12

// The fixed parameters of a recovery file (core §2.6, L19, L20; KEL §2.12). None is configurable,
// and a file that names other argon2id parameters is refused before any key is derived, so a
// crafted file cannot make the reader spend more memory or time than these.
const (
	recoveryType   = "anet.recovery/1"  // RecoveryBlob key 0 (L20)
	recoveryHeader = "anet-recovery v1" // the first line of the text (CORE-K10)
	nextKeyLabel   = "anet-kel-next/v1" // L19, the HKDF salt

	kdfArgon2id   = "argon2id"
	kdfLocal      = "local"
	recoveryAEAD  = "xchacha20poly1305"
	argon2Time    = 3
	argon2MemKiB  = 64 * 1024
	argon2Lanes   = 4
	recoverySalt  = 16
	recoveryNonce = chacha20poly1305.NonceSizeX // 24
	recoveryRSLen = 32

	// recoveryBase64Line is the width of the base64 block's lines.
	recoveryBase64Line = 64
	// maxRecoveryHubLen bounds the hub hint. A URL longer than this is not a hub address; the bound
	// keeps every file this package writes within maxRecoveryFileLen.
	maxRecoveryHubLen = 2048
	// maxRecoveryFileLen bounds what ParseRecoveryFile reads. A file this package writes is about
	// 500 bytes plus the hub hint and the note.
	maxRecoveryFileLen = 16 << 10
)

// Errors. The returned errors wrap these with detail; use errors.Is.
var (
	// ErrRecoveryFormat: the bytes are not a well-formed recovery file, the sealed seed does not
	// match the commitment the file states, a local-key file does not open under the local key it
	// was given (the file or recovery_local.key was changed), or a passphrase file was handed to
	// OpenRecoveryFileLocal.
	ErrRecoveryFormat = errors.New("identity: not a valid recovery file")
	// ErrRecoveryPassphrase: the passphrase file does not open with this passphrase. A wrong
	// passphrase and an altered ciphertext look the same (C-35).
	ErrRecoveryPassphrase = errors.New("identity: the recovery file does not open with this passphrase")
	// ErrRecoveryUnprotected: OpenRecoveryFile was handed a file that has no passphrase yet (kdf
	// local). It opens only with recovery_local.key, beside it in its own data directory; it
	// cannot be used to recover on another machine (C-37, recovery_file_unprotected).
	ErrRecoveryUnprotected = errors.New("identity: the recovery file has no passphrase yet; it opens only with the local recovery key of its own data directory")
	// ErrRecoveryWrongIdentity: the text header names another AID, hub or commitment than the
	// block does, so the file was altered (C-33, C-37; recovery_wrong_identity).
	ErrRecoveryWrongIdentity = errors.New("identity: the recovery file's header does not match its sealed block")
	// ErrPassphraseTooShort: fewer than MinPassphraseRunes code points after NFC (C-34;
	// passphrase_too_short).
	ErrPassphraseTooShort = errors.New("identity: the recovery passphrase is shorter than 12 characters")
	// ErrNextKeyInput: the AID or the seed cannot be used for next-key derivation: the AID is empty,
	// is not valid UTF-8 or holds U+0000 (CORE-E9: with U+0000 two (aid, seq) pairs could derive
	// alike), or the seed is all zero.
	ErrNextKeyInput = errors.New("identity: not a usable input for next-key derivation")
)

// Commit is the commitment a recovery seed made when its file was written: Digest is
// NextDigest(rs, aid, Seq), the next_digest of the key that the event at Seq will reveal. The
// first join writes {2, NextDigest(rs, aid, 2)} (C-31). It is public (it is in the KEL).
type Commit struct {
	Seq    uint64
	Digest [sha256.Size]byte
}

// RecoveryFileInfo is what a recovery file states about itself, read without opening it. All of it
// is public.
type RecoveryFileInfo struct {
	AID     string
	Hub     string // the hub hint; "" when the file has none
	Commits Commit
	// Unprotected is true for a file sealed under a data directory's local recovery key (kdf
	// local): OpenRecoveryFile refuses it, OpenRecoveryFileLocal opens it.
	Unprotected bool
}

// RecoveryBlob is the base64 block of a recovery file (core §2.6). The aad of its ciphertext is
// coredet of the blob without key 7, which is what encoding it with CT nil gives.
//
//anet:wire RecoveryBlob
type recoveryBlob struct {
	Type    string          `cbor:"0,keyasint"` // recoveryType
	AID     string          `cbor:"1,keyasint"`
	KDF     recoveryKDF     `cbor:"2,keyasint"`
	AEAD    string          `cbor:"3,keyasint"` // recoveryAEAD
	Nonce   []byte          `cbor:"4,keyasint"` // 24 bytes
	Hub     string          `cbor:"5,keyasint"` // written even when ""
	Commits recoveryCommits `cbor:"6,keyasint"`
	CT      []byte          `cbor:"7,keyasint,omitempty"` // RS sealed: 32 + 16 bytes; nil in the aad
}

// RecoveryKDF is key 2 of a RecoveryBlob: exactly {1: "argon2id", 2: 3, 3: 65536, 4: 4, 5: salt}
// or {1: "local"}. omitempty leaves the argon2id keys out of the local shape.
//
//anet:wire RecoveryKDF
type recoveryKDF struct {
	Alg  string `cbor:"1,keyasint"`
	T    uint64 `cbor:"2,keyasint,omitempty"`
	MKiB uint64 `cbor:"3,keyasint,omitempty"`
	P    uint64 `cbor:"4,keyasint,omitempty"`
	Salt []byte `cbor:"5,keyasint,omitempty"`
}

// recoveryCommits is key 6 of a RecoveryBlob: [seq, next_digest].
type recoveryCommits struct {
	_      struct{} `cbor:",toarray"`
	Seq    uint64
	Digest []byte
}

// ---- next-key derivation (L19) ------------------------------------------------------------------

// RecoverySeed returns key(aid, seq), the key the rot or dip at seq reveals, derived from the
// recovery seed rs (L19, C-30). It refuses an AID that is empty, not valid UTF-8 or holds U+0000
// (CORE-E9), and an all-zero seed. The caller clears rs and the key when done.
func RecoverySeed(rs [32]byte, aid string, seq uint64) (ed25519.PrivateKey, error) {
	s, err := nextSeed(rs, aid, seq)
	if err != nil {
		return nil, err
	}
	defer clear(s)
	return ed25519.NewKeyFromSeed(s), nil
}

// NextDigest returns next_digest(aid, seq): the SHA-256 of the public key of RecoverySeed(rs, aid,
// seq), which is what a rot at seq-1 commits to in KeyEvent key 6 (L19, C-30). It refuses what
// RecoverySeed refuses.
func NextDigest(rs [32]byte, aid string, seq uint64) ([32]byte, error) {
	k, err := RecoverySeed(rs, aid, seq)
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(k)
	return sha256.Sum256(k.Public().(ed25519.PublicKey)), nil
}

// nextSeed is seed(aid, seq) of L19.
func nextSeed(rs [32]byte, aid string, seq uint64) ([]byte, error) {
	switch {
	case aid == "":
		return nil, fmt.Errorf("%w: the AID is empty", ErrNextKeyInput)
	case strings.IndexByte(aid, 0) >= 0:
		return nil, fmt.Errorf("%w: the AID holds U+0000", ErrNextKeyInput)
	case !utf8.ValidString(aid):
		return nil, fmt.Errorf("%w: the AID is not valid UTF-8", ErrNextKeyInput)
	case rs == [32]byte{}:
		return nil, fmt.Errorf("%w: the recovery seed is all zero", ErrNextKeyInput)
	}
	info := make([]byte, 0, len(aid)+1+8)
	info = append(info, aid...)
	info = append(info, 0)
	info = binary.BigEndian.AppendUint64(info, seq)
	return hkdf.Key(sha256.New, rs[:], []byte(nextKeyLabel), string(info), ed25519.SeedSize)
}

// ---- passphrases (C-34) -------------------------------------------------------------------------

// CheckPassphrase reports whether p may protect a recovery file: at least MinPassphraseRunes code
// points after NFC (ErrPassphraseTooShort). The CLI checks the first entry with it before asking
// for the second.
func CheckPassphrase(p []byte) error {
	n := nfc(p)
	defer clear(n)
	if c := utf8.RuneCount(n); c < MinPassphraseRunes {
		return fmt.Errorf("%w (%d after normalization)", ErrPassphraseTooShort, c)
	}
	return nil
}

// nfc returns the NFC form of p in a new buffer the caller may clear: norm's Bytes can return p
// itself, which the caller does not own.
func nfc(p []byte) []byte { return norm.NFC.Append(nil, p...) }

// passphraseKey is argon2id over an NFC passphrase (L20). It is a variable only so that this
// package's property tests can put a fast stand-in in its place for the cases where the key
// derivation is not what is under test; nothing else assigns it.
var passphraseKey = func(nfcPass, salt []byte) []byte {
	return argon2.IDKey(nfcPass, salt, argon2Time, argon2MemKiB, argon2Lanes, chacha20poly1305.KeySize)
}

// ---- sealing ------------------------------------------------------------------------------------

// SealRecoveryFile returns the text of a passphrase-protected recovery file for rs (C-35): a fresh
// random 16-byte salt and 24-byte nonce (C-34), argon2id over the NFC passphrase. hub is the
// witness hub URL as a hint, or "". commits must be what rs commits to (Commit); aid must be a
// usable AID without white space. Add the note lines with WithRecoveryNote.
func SealRecoveryFile(rs [32]byte, aid, hub string, commits Commit, passphrase []byte) ([]byte, error) {
	salt := make([]byte, recoverySalt)
	nonce := make([]byte, recoveryNonce)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return sealRecoveryPassphrase(rs, aid, hub, commits, passphrase, salt, nonce)
}

// SealRecoveryFileLocal returns the text of a recovery file that has no passphrase yet (C-36): rs
// sealed under localKey, the 32 bytes of the data directory's recovery_local.key, with a fresh
// random nonce. Otherwise as SealRecoveryFile. An all-zero localKey is refused.
func SealRecoveryFileLocal(rs [32]byte, aid, hub string, commits Commit, localKey [32]byte) ([]byte, error) {
	nonce := make([]byte, recoveryNonce)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return sealRecoveryLocal(rs, aid, hub, commits, localKey, nonce)
}

// sealRecoveryPassphrase is SealRecoveryFile with the salt and nonce given (the golden vectors fix
// them).
func sealRecoveryPassphrase(rs [32]byte, aid, hub string, commits Commit, passphrase, salt, nonce []byte) ([]byte, error) {
	if err := CheckPassphrase(passphrase); err != nil {
		return nil, err
	}
	if len(salt) != recoverySalt {
		return nil, errors.New("identity: a recovery salt is 16 bytes")
	}
	n := nfc(passphrase)
	defer clear(n)
	key := passphraseKey(n, salt)
	defer clear(key)
	kdf := recoveryKDF{Alg: kdfArgon2id, T: argon2Time, MKiB: argon2MemKiB, P: argon2Lanes, Salt: bytes.Clone(salt)}
	return sealRecovery(rs, aid, hub, commits, kdf, key, nonce)
}

// sealRecoveryLocal is SealRecoveryFileLocal with the nonce given.
func sealRecoveryLocal(rs [32]byte, aid, hub string, commits Commit, localKey [32]byte, nonce []byte) ([]byte, error) {
	if localKey == [32]byte{} {
		return nil, errors.New("identity: the local recovery key is all zero")
	}
	return sealRecovery(rs, aid, hub, commits, recoveryKDF{Alg: kdfLocal}, localKey[:], nonce)
}

// sealRecovery checks what the file will state, seals rs under key and renders the text.
func sealRecovery(rs [32]byte, aid, hub string, commits Commit, kdf recoveryKDF, key, nonce []byte) ([]byte, error) {
	if err := checkHeaderAID(aid); err != nil {
		return nil, err
	}
	if err := checkHub(hub); err != nil {
		return nil, err
	}
	if len(nonce) != recoveryNonce {
		return nil, errors.New("identity: a recovery nonce is 24 bytes")
	}
	want, err := NextDigest(rs, aid, commits.Seq)
	if err != nil {
		return nil, err
	}
	if want != commits.Digest {
		return nil, fmt.Errorf("identity: commits is not what this recovery seed commits to at seq %d", commits.Seq)
	}
	b := &recoveryBlob{Type: recoveryType, AID: aid, KDF: kdf, AEAD: recoveryAEAD, Nonce: bytes.Clone(nonce), Hub: hub,
		Commits: recoveryCommits{Seq: commits.Seq, Digest: bytes.Clone(commits.Digest[:])}}
	aad, err := b.aad()
	if err != nil {
		return nil, err
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	b.CT = a.Seal(nil, b.Nonce, rs[:], aad)
	raw, err := coredet.Marshal(b)
	if err != nil {
		return nil, err
	}
	return renderRecovery(b, raw), nil
}

// aad is coredet(RecoveryBlob without key 7) (L20).
func (b *recoveryBlob) aad() ([]byte, error) {
	c := *b
	c.CT = nil
	return coredet.Marshal(&c)
}

// renderRecovery writes the text of a recovery file whose block is raw (the coredet bytes of b).
func renderRecovery(b *recoveryBlob, raw []byte) []byte {
	var w bytes.Buffer
	w.WriteString(recoveryHeader + "\n")
	w.WriteString("AID " + b.AID + "\n")
	if b.Hub != "" {
		w.WriteString("hub " + b.Hub + "\n")
	}
	fmt.Fprintf(&w, "commits %d %x\n\n", b.Commits.Seq, b.Commits.Digest)
	enc := base64.StdEncoding.EncodeToString(raw)
	for len(enc) > recoveryBase64Line {
		w.WriteString(enc[:recoveryBase64Line] + "\n")
		enc = enc[recoveryBase64Line:]
	}
	w.WriteString(enc + "\n")
	return w.Bytes()
}

// WithRecoveryNote returns file (a recovery file as SealRecoveryFile or SealRecoveryFileLocal
// wrote it, without a note) with a blank line and the note lines appended: the sentence the
// caller's reason table holds for the file, in Chinese and in English (KEL §2.4, C-36). Readers
// ignore the note. Each line must be non-empty, valid UTF-8 and free of control characters, and
// the noted file must still read back (file ends in a line end, and the whole stays within the size
// a reader accepts), so that a file nobody could read at recovery time is never written.
func WithRecoveryNote(file []byte, lines ...string) ([]byte, error) {
	f, err := parseRecovery(file)
	if err != nil {
		return nil, err
	}
	if f.noted {
		return nil, errors.New("identity: the recovery file already has a note")
	}
	if len(lines) == 0 {
		return nil, errors.New("identity: no note lines")
	}
	out := bytes.Clone(file)
	out = append(out, '\n')
	for _, l := range lines {
		if l == "" || !utf8.ValidString(l) || strings.IndexFunc(l, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("identity: a recovery note line must be one non-empty line of text: %q", l)
		}
		out = append(out, l...)
		out = append(out, '\n')
	}
	if _, err := parseRecovery(out); err != nil {
		return nil, fmt.Errorf("identity: the recovery file with this note would not read back: %v", err)
	}
	return out, nil
}

// ---- opening ------------------------------------------------------------------------------------

// OpenRecoveryFile opens a passphrase-protected recovery file (C-35) and returns the seed and what
// the file states. Errors: ErrRecoveryFormat, ErrRecoveryWrongIdentity, ErrRecoveryUnprotected
// (the file has no passphrase yet: kdf local), ErrRecoveryPassphrase (the passphrase does not open
// it). The caller compares aid with the identity it acts for, and clears rs and passphrase.
func OpenRecoveryFile(b, passphrase []byte) (rs [32]byte, aid, hub string, commits Commit, err error) {
	f, err := parseRecovery(b)
	if err != nil {
		return rs, "", "", Commit{}, err
	}
	if f.blob.KDF.Alg != kdfArgon2id {
		return rs, "", "", Commit{}, ErrRecoveryUnprotected
	}
	n := nfc(passphrase)
	defer clear(n)
	key := passphraseKey(n, f.blob.KDF.Salt)
	defer clear(key)
	if rs, err = f.open(key); err != nil {
		if errors.Is(err, errAEAD) {
			err = ErrRecoveryPassphrase
		}
		return [32]byte{}, "", "", Commit{}, err
	}
	return rs, f.blob.AID, f.blob.Hub, f.commit(), nil
}

// OpenRecoveryFileLocal opens a recovery file that has no passphrase yet (C-36) with the 32
// bytes of the data directory's recovery_local.key. A passphrase file (kdf argon2id), a key that
// does not open it, and an all-zero key are ErrRecoveryFormat: the file or the key was changed.
// Otherwise as OpenRecoveryFile.
func OpenRecoveryFileLocal(b []byte, localKey [32]byte) (rs [32]byte, aid, hub string, commits Commit, err error) {
	f, err := parseRecovery(b)
	if err != nil {
		return rs, "", "", Commit{}, err
	}
	if f.blob.KDF.Alg != kdfLocal {
		return rs, "", "", Commit{}, fmt.Errorf("%w: it is protected by a passphrase, not by the local recovery key", ErrRecoveryFormat)
	}
	if localKey == [32]byte{} {
		return rs, "", "", Commit{}, fmt.Errorf("%w: the local recovery key is all zero", ErrRecoveryFormat)
	}
	if rs, err = f.open(localKey[:]); err != nil {
		if errors.Is(err, errAEAD) {
			err = fmt.Errorf("%w: it does not open with this local recovery key (the file or the key was changed)", ErrRecoveryFormat)
		}
		return [32]byte{}, "", "", Commit{}, err
	}
	return rs, f.blob.AID, f.blob.Hub, f.commit(), nil
}

// ParseRecoveryFile reads what a recovery file states without opening it: no passphrase or key is
// needed, and nothing secret is returned. The CLI uses it to see whether a file is unprotected
// before asking for a passphrase, and to compare a file's commitment with the identity's.
// Errors: ErrRecoveryFormat, ErrRecoveryWrongIdentity.
func ParseRecoveryFile(b []byte) (RecoveryFileInfo, error) {
	f, err := parseRecovery(b)
	if err != nil {
		return RecoveryFileInfo{}, err
	}
	return RecoveryFileInfo{AID: f.blob.AID, Hub: f.blob.Hub, Commits: f.commit(), Unprotected: f.blob.KDF.Alg == kdfLocal}, nil
}

// errAEAD is the AEAD refusing the ciphertext; the callers turn it into their mode's error.
var errAEAD = errors.New("identity: the recovery block does not open")

// recoveryFile is a parsed recovery file.
type recoveryFile struct {
	blob  recoveryBlob
	noted bool // something follows the block
}

func (f *recoveryFile) commit() Commit {
	c := Commit{Seq: f.blob.Commits.Seq}
	copy(c.Digest[:], f.blob.Commits.Digest)
	return c
}

// open decrypts the block under key and checks that the seed commits to what the file states.
func (f *recoveryFile) open(key []byte) ([32]byte, error) {
	var rs [32]byte
	aad, err := f.blob.aad()
	if err != nil {
		return rs, fmt.Errorf("%w: %v", ErrRecoveryFormat, err)
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return rs, err
	}
	pt, err := a.Open(nil, f.blob.Nonce, f.blob.CT, aad)
	if err != nil {
		return rs, errAEAD
	}
	defer clear(pt)
	if len(pt) != recoveryRSLen {
		return rs, fmt.Errorf("%w: the sealed seed is not 32 bytes", ErrRecoveryFormat)
	}
	copy(rs[:], pt)
	d, err := NextDigest(rs, f.blob.AID, f.blob.Commits.Seq)
	if err != nil || !bytes.Equal(d[:], f.blob.Commits.Digest) {
		clear(rs[:])
		return [32]byte{}, fmt.Errorf("%w: the sealed seed does not commit to what the file states", ErrRecoveryFormat)
	}
	return rs, nil
}

// parseRecovery reads the text and the block (C-33, C-37). The block is the authority: it decodes
// strictly and canonically, and the header must state exactly what it states. A leading byte-order
// mark and CRLF line ends are tolerated, since a file copied through another system may gain them
// and the block is unaffected.
func parseRecovery(b []byte) (*recoveryFile, error) {
	if len(b) > maxRecoveryFileLen {
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrRecoveryFormat, maxRecoveryFileLen)
	}
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%w: not UTF-8 text", ErrRecoveryFormat)
	}
	text := strings.TrimPrefix(string(b), "\ufeff")
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	if lines[0] != recoveryHeader {
		return nil, fmt.Errorf("%w: the first line is not %q", ErrRecoveryFormat, recoveryHeader)
	}
	// header: "AID <aid>", optionally "hub <url>", "commits <seq> <hex>", up to a blank line
	var hAID, hHub, hCommits string
	seen := map[string]bool{}
	i := 1
	for ; i < len(lines) && lines[i] != ""; i++ {
		k, v, ok := strings.Cut(lines[i], " ")
		if !ok || v == "" || seen[k] {
			return nil, fmt.Errorf("%w: header line %d is not one of AID, hub, commits with a value, each once", ErrRecoveryFormat, i+1)
		}
		seen[k] = true
		switch k {
		case "AID":
			hAID = v
		case "hub":
			hHub = v
		case "commits":
			hCommits = v
		default:
			return nil, fmt.Errorf("%w: header line %d is not one of AID, hub, commits", ErrRecoveryFormat, i+1)
		}
	}
	if !seen["AID"] || !seen["commits"] {
		return nil, fmt.Errorf("%w: the header lacks the AID or commits line", ErrRecoveryFormat)
	}
	hc, err := parseCommitsLine(hCommits)
	if err != nil {
		return nil, err
	}
	// the block: base64 lines from after the blank line up to the next blank line or the end
	i++
	var enc strings.Builder
	for ; i < len(lines) && lines[i] != ""; i++ {
		enc.WriteString(lines[i])
	}
	noted := false
	for ; i < len(lines); i++ {
		noted = noted || lines[i] != ""
	}
	if enc.Len() == 0 {
		return nil, fmt.Errorf("%w: no base64 block after the header", ErrRecoveryFormat)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(enc.String())
	if err != nil {
		return nil, fmt.Errorf("%w: the block is not base64", ErrRecoveryFormat)
	}
	blob, err := decodeRecoveryBlob(raw)
	if err != nil {
		return nil, err
	}
	if hAID != blob.AID || hc.Seq != blob.Commits.Seq || !bytes.Equal(hc.Digest[:], blob.Commits.Digest) ||
		seen["hub"] && hHub != blob.Hub {
		return nil, ErrRecoveryWrongIdentity
	}
	return &recoveryFile{blob: *blob, noted: noted}, nil
}

// parseCommitsLine reads "<seq> <64 lower-case hex digits>", seq in decimal without leading zeros.
func parseCommitsLine(v string) (Commit, error) {
	var c Commit
	s, h, ok := strings.Cut(v, " ")
	if !ok || s == "" || (len(s) > 1 && s[0] == '0') || len(h) != 2*sha256.Size || strings.ToLower(h) != h {
		return c, fmt.Errorf("%w: the commits line is not \"<seq> <64 hex digits>\"", ErrRecoveryFormat)
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return c, fmt.Errorf("%w: the commits seq is not a decimal number", ErrRecoveryFormat)
		}
	}
	seq, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return c, fmt.Errorf("%w: the commits seq is not a decimal number", ErrRecoveryFormat)
	}
	d, err := hex.DecodeString(h)
	if err != nil {
		return c, fmt.Errorf("%w: the commits digest is not hex", ErrRecoveryFormat)
	}
	c.Seq = seq
	copy(c.Digest[:], d)
	return c, nil
}

// decodeRecoveryBlob decodes the block strictly (CORE-E4) and canonically (the bytes are coredet of
// what they decode to, so a required key cannot be missing), and checks every key: the type tag,
// one of the two kdf shapes with exactly the fixed argon2id parameters, the AEAD, the sizes.
func decodeRecoveryBlob(raw []byte) (*recoveryBlob, error) {
	var b recoveryBlob
	if err := coredet.UnmarshalStrict(raw, &b); err != nil {
		return nil, fmt.Errorf("%w: the block does not decode: %v", ErrRecoveryFormat, err)
	}
	back, err := coredet.Marshal(&b)
	if err != nil || !bytes.Equal(back, raw) {
		return nil, fmt.Errorf("%w: the block is not in canonical form, or lacks a required key", ErrRecoveryFormat)
	}
	switch {
	case b.Type != recoveryType:
		return nil, fmt.Errorf("%w: key 0 is not %q", ErrRecoveryFormat, recoveryType)
	case checkHeaderAID(b.AID) != nil:
		return nil, fmt.Errorf("%w: key 1 is not a usable AID", ErrRecoveryFormat)
	case !validKDF(b.KDF):
		return nil, fmt.Errorf("%w: key 2 is neither the argon2id nor the local key derivation", ErrRecoveryFormat)
	case b.AEAD != recoveryAEAD:
		return nil, fmt.Errorf("%w: key 3 is not %q", ErrRecoveryFormat, recoveryAEAD)
	case len(b.Nonce) != recoveryNonce:
		return nil, fmt.Errorf("%w: key 4 is not a 24-byte nonce", ErrRecoveryFormat)
	case checkHub(b.Hub) != nil:
		return nil, fmt.Errorf("%w: key 5 is not a usable hub hint", ErrRecoveryFormat)
	case len(b.Commits.Digest) != sha256.Size:
		return nil, fmt.Errorf("%w: key 6 does not hold a 32-byte digest", ErrRecoveryFormat)
	case len(b.CT) != recoveryRSLen+chacha20poly1305.Overhead:
		return nil, fmt.Errorf("%w: key 7 is not a sealed 32-byte seed", ErrRecoveryFormat)
	}
	return &b, nil
}

// validKDF is the two shapes of RecoveryKDF (core §2.6).
func validKDF(k recoveryKDF) bool {
	switch k.Alg {
	case kdfArgon2id:
		return k.T == argon2Time && k.MKiB == argon2MemKiB && k.P == argon2Lanes && len(k.Salt) == recoverySalt
	case kdfLocal:
		return k.T == 0 && k.MKiB == 0 && k.P == 0 && len(k.Salt) == 0
	}
	return false
}

// checkHeaderAID: the AID goes into L19 (no U+0000, CORE-E9) and into a header line (no white space
// or control character, which would break the line).
func checkHeaderAID(aid string) error {
	if aid == "" || !utf8.ValidString(aid) || strings.IndexFunc(aid, notTokenRune) >= 0 {
		return fmt.Errorf("identity: %q is not a usable AID for a recovery file", aid)
	}
	return nil
}

// checkHub: the hub hint is "" or one header token of at most maxRecoveryHubLen bytes.
func checkHub(hub string) error {
	if len(hub) > maxRecoveryHubLen || !utf8.ValidString(hub) || strings.IndexFunc(hub, notTokenRune) >= 0 {
		return fmt.Errorf("identity: the hub hint must be one line without spaces, at most %d bytes", maxRecoveryHubLen)
	}
	return nil
}

func notTokenRune(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r == '\ufeff' }
