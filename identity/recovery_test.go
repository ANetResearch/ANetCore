package identity

// Recovery seed and recovery file (KEL §2.3, §2.4, C-30–C-37; core §2.6, L19, L20, RECOVERY-1).
//
// RECOVERY-1 (testdata/vec-recovery-1.json) is generated twice, here and by the independent Python
// implementation in golden/py/gen_v016.py, and both must write the same bytes (CI golden-xcheck):
//
//	go test ./identity -run TestRECOVERY1Vector -update     rewrites it (and the KEL vectors)
//	python3 golden/py/gen_v016.py check RECOVERY-1          checks the Python side

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/ANetResearch/ANetCore/coredet"
)

// ---- KDF stand-ins ------------------------------------------------------------------------------

// withFastKDF puts a fast stand-in in place of argon2id for a test in which the key derivation is
// not what is under test (the format, the AEAD binding, the mode checks). The passphrase reaching
// it is already NFC: normalization stays under test.
func withFastKDF(tb testing.TB) {
	tb.Helper()
	old := passphraseKey
	passphraseKey = func(p, salt []byte) []byte {
		h := sha256.New()
		h.Write([]byte("fast stand-in for argon2id"))
		h.Write(salt)
		h.Write(p)
		return h.Sum(nil)
	}
	tb.Cleanup(func() { passphraseKey = old })
}

// withCachedKDF keeps argon2id but computes each (passphrase, salt) once.
func withCachedKDF(tb testing.TB) {
	tb.Helper()
	old := passphraseKey
	cache := map[string][]byte{}
	passphraseKey = func(p, salt []byte) []byte {
		k := hex.EncodeToString(salt) + "/" + hex.EncodeToString(p)
		if v, ok := cache[k]; ok {
			return bytes.Clone(v) // the caller clears what it gets
		}
		v := old(p, salt)
		cache[k] = bytes.Clone(v)
		return v
	}
	tb.Cleanup(func() { passphraseKey = old })
}

// ---- RECOVERY-1 ---------------------------------------------------------------------------------

const (
	recVID        = "RECOVERY-1"
	recPassphrase = "anet recovery vector passphrase v1"
	recHub        = "https://hub.example"
	recAbout      = "Recovery seed and recovery file (L19, L20). aid is the KEL-2B agent; rs = SHA-256 of rs_label. " +
		"next_keys: seed = HKDF-SHA256(ikm = rs, salt = \"anet-kel-next/v1\", info = UTF-8(aid) || 0x00 || u64be(seq), L = 32), " +
		"pub its Ed25519 public key, next_digest = SHA-256(pub). " +
		"passphrase_file: salt is the first 16 and nonce the first 24 bytes of SHA-256 of their labels; " +
		"key = argon2id(NFC(passphrase), salt, t = 3, m = 65536 KiB, p = 4, 32); aad = coredet(RecoveryBlob without key 7); " +
		"blob = coredet(RecoveryBlob) with ct = XChaCha20-Poly1305(key, nonce, rs, aad); text is the file as written, " +
		"before the caller's note lines. local_file: the same seed under kdf {1: \"local\"}, key = local_key = SHA-256 of its label. " +
		"Each negative is a file opened with the interface and secret given, and the error class it must give; " +
		"each derive negative is refused by next-key derivation."
)

func recLabel(role string) string { return "anet-golden/v016/" + recVID + "/" + role }

func recSeed(role string) []byte {
	s := sha256.Sum256([]byte(recLabel(role)))
	return s[:]
}

type recNextKey struct {
	Seq        uint64 `json:"seq"`
	Seed       string `json:"seed"`
	Pub        string `json:"pub"`
	NextDigest string `json:"next_digest"`
}

type recCommits struct {
	Seq        uint64 `json:"seq"`
	NextDigest string `json:"next_digest"`
}

type recPassFile struct {
	Passphrase string     `json:"passphrase"`
	SaltLabel  string     `json:"salt_label"`
	Salt       string     `json:"salt"`
	NonceLabel string     `json:"nonce_label"`
	Nonce      string     `json:"nonce"`
	Hub        string     `json:"hub"`
	Commits    recCommits `json:"commits"`
	Key        string     `json:"key"`
	AAD        string     `json:"aad"`
	Blob       string     `json:"blob"`
	Text       string     `json:"text"`
}

type recLocalFile struct {
	LocalKeyLabel string     `json:"local_key_label"`
	LocalKey      string     `json:"local_key"`
	NonceLabel    string     `json:"nonce_label"`
	Nonce         string     `json:"nonce"`
	Hub           string     `json:"hub"`
	Commits       recCommits `json:"commits"`
	AAD           string     `json:"aad"`
	Blob          string     `json:"blob"`
	Text          string     `json:"text"`
}

type recNegative struct {
	Name       string `json:"name"`
	Open       string `json:"open"` // "passphrase" (OpenRecoveryFile) or "local" (OpenRecoveryFileLocal)
	Passphrase string `json:"passphrase,omitempty"`
	LocalKey   string `json:"local_key,omitempty"`
	Text       string `json:"text"`
	Error      string `json:"error"`
}

type recDeriveNegative struct {
	Name  string `json:"name"`
	AID   string `json:"aid"`
	Seq   uint64 `json:"seq"`
	Error string `json:"error"`
}

type recoveryVector struct {
	ID              string              `json:"id"`
	About           string              `json:"about"`
	AID             string              `json:"aid"`
	RSLabel         string              `json:"rs_label"`
	RS              string              `json:"rs"`
	NextKeys        []recNextKey        `json:"next_keys"`
	PassphraseFile  recPassFile         `json:"passphrase_file"`
	LocalFile       recLocalFile        `json:"local_file"`
	Negatives       []recNegative       `json:"negatives"`
	DeriveNegatives []recDeriveNegative `json:"derive_negatives"`
}

// The error classes of the vector.
var recErrClass = map[string]error{
	"recovery-format":         ErrRecoveryFormat,
	"recovery-passphrase":     ErrRecoveryPassphrase,
	"recovery-unprotected":    ErrRecoveryUnprotected,
	"recovery-wrong-identity": ErrRecoveryWrongIdentity,
	"next-key-input":          ErrNextKeyInput,
}

// recBlob seals rs under key into a blob with exactly the given fields, checking nothing: the
// vector's negatives need blobs Seal would not make.
func recBlob(tb testing.TB, aid, hub string, kdf recoveryKDF, nonce []byte, c Commit, key []byte, rs [32]byte) (*recoveryBlob, []byte) {
	tb.Helper()
	b := &recoveryBlob{Type: recoveryType, AID: aid, KDF: kdf, AEAD: recoveryAEAD, Nonce: nonce, Hub: hub,
		Commits: recoveryCommits{Seq: c.Seq, Digest: bytes.Clone(c.Digest[:])}}
	aad, err := b.aad()
	if err != nil {
		tb.Fatal(err)
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		tb.Fatal(err)
	}
	b.CT = a.Seal(nil, nonce, rs[:], aad)
	raw, err := coredet.Marshal(b)
	if err != nil {
		tb.Fatal(err)
	}
	return b, raw
}

// recMapEdit decodes a blob to its map, applies edit and re-encodes it canonically.
func recMapEdit(tb testing.TB, raw []byte, edit func(m map[uint64]cbor.RawMessage)) []byte {
	tb.Helper()
	m := map[uint64]cbor.RawMessage{}
	if err := coredet.Unmarshal(raw, &m); err != nil {
		tb.Fatal(err)
	}
	edit(m)
	out, err := coredet.Marshal(m)
	if err != nil {
		tb.Fatal(err)
	}
	return out
}

func recFlip(b []byte, i int) []byte {
	out := bytes.Clone(b)
	if i < 0 {
		i += len(out)
	}
	out[i] ^= 1
	return out
}

func recReplace(tb testing.TB, s, old, new string) string {
	tb.Helper()
	if strings.Count(s, old) != 1 {
		tb.Fatalf("%q occurs %d times", old, strings.Count(s, old))
	}
	return strings.Replace(s, old, new, 1)
}

func mustDigest(tb testing.TB, rs [32]byte, aid string, seq uint64) [32]byte {
	tb.Helper()
	d, err := NextDigest(rs, aid, seq)
	if err != nil {
		tb.Fatal(err)
	}
	return d
}

// recoveryVectorFile is RECOVERY-1 as this implementation generates it.
func recoveryVectorFile(t testing.TB) []byte {
	t.Helper()
	aid := kel2B()[0].EventID
	var rs [32]byte
	copy(rs[:], recSeed("rs"))
	v := recoveryVector{ID: recVID, About: recAbout, AID: aid, RSLabel: recLabel("rs"), RS: hex.EncodeToString(rs[:])}
	for seq := uint64(2); seq <= 4; seq++ {
		s, err := nextSeed(rs, aid, seq)
		if err != nil {
			t.Fatal(err)
		}
		pub := ed25519.NewKeyFromSeed(s).Public().(ed25519.PublicKey)
		d := sha256.Sum256(pub)
		v.NextKeys = append(v.NextKeys, recNextKey{Seq: seq, Seed: hex.EncodeToString(s), Pub: hex.EncodeToString(pub), NextDigest: hex.EncodeToString(d[:])})
	}
	commits := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	rc := recCommits{Seq: 2, NextDigest: hex.EncodeToString(commits.Digest[:])}

	// the passphrase file
	salt, nonce := recSeed("salt")[:recoverySalt], recSeed("nonce")[:recoveryNonce]
	text, err := sealRecoveryPassphrase(rs, aid, recHub, commits, []byte(recPassphrase), salt, nonce)
	if err != nil {
		t.Fatal(err)
	}
	pf, err := parseRecovery(text)
	if err != nil {
		t.Fatal(err)
	}
	pAAD, _ := pf.blob.aad()
	pRaw, _ := coredet.Marshal(&pf.blob)
	key := passphraseKey(nfc([]byte(recPassphrase)), salt)
	v.PassphraseFile = recPassFile{Passphrase: recPassphrase, SaltLabel: recLabel("salt"), Salt: hex.EncodeToString(salt),
		NonceLabel: recLabel("nonce"), Nonce: hex.EncodeToString(nonce), Hub: recHub, Commits: rc, Key: hex.EncodeToString(key),
		AAD: hex.EncodeToString(pAAD), Blob: hex.EncodeToString(pRaw), Text: string(text)}

	// the local file
	var lk [32]byte
	copy(lk[:], recSeed("local-key"))
	lnonce := recSeed("local-nonce")[:recoveryNonce]
	ltext, err := sealRecoveryLocal(rs, aid, recHub, commits, lk, lnonce)
	if err != nil {
		t.Fatal(err)
	}
	lf, err := parseRecovery(ltext)
	if err != nil {
		t.Fatal(err)
	}
	lAAD, _ := lf.blob.aad()
	lRaw, _ := coredet.Marshal(&lf.blob)
	v.LocalFile = recLocalFile{LocalKeyLabel: recLabel("local-key"), LocalKey: hex.EncodeToString(lk[:]), NonceLabel: recLabel("local-nonce"),
		Nonce: hex.EncodeToString(lnonce), Hub: recHub, Commits: rc, AAD: hex.EncodeToString(lAAD), Blob: hex.EncodeToString(lRaw), Text: string(ltext)}

	// the negatives
	pt, lt := string(text), string(ltext)
	render := func(b *recoveryBlob, raw []byte) string { return string(renderRecovery(b, raw)) }
	pass := func(name, text, class string) recNegative {
		return recNegative{Name: name, Open: "passphrase", Passphrase: recPassphrase, Text: text, Error: class}
	}
	local := func(name, text string, key []byte, class string) recNegative {
		return recNegative{Name: name, Open: "local", LocalKey: hex.EncodeToString(key), Text: text, Error: class}
	}
	other := kel2A()[0].EventID
	d3 := mustDigest(t, rs, aid, 3)
	pb := &pf.blob
	nonCanon := bytes.Replace(pRaw, []byte{0x82, 0x02, 0x58, 0x20}, []byte{0x82, 0x18, 0x02, 0x58, 0x20}, -1)
	if bytes.Count(pRaw, []byte{0x82, 0x02, 0x58, 0x20}) != 1 {
		t.Fatal("the commits array is not found once in the block")
	}
	tBlob := *pb
	tBlob.KDF.T = 4
	tRaw, _ := coredet.Marshal(&tBlob)
	_, wrongCommits := recBlob(t, aid, recHub, pb.KDF, nonce, Commit{Seq: 2, Digest: d3}, key, rs)
	wcBlob := *pb
	wcBlob.Commits.Digest = d3[:]
	relabelled := *pb
	relabelled.KDF = recoveryKDF{Alg: kdfLocal}
	relRaw, _ := coredet.Marshal(&relabelled)
	wrongLocal := recSeed("wrong-local-key")
	v.Negatives = []recNegative{
		{Name: "wrong passphrase", Open: "passphrase", Passphrase: "anet recovery vector passphrase v2", Text: pt, Error: "recovery-passphrase"},
		pass("AID in the header changed", recReplace(t, pt, "AID "+aid+"\n", "AID "+other+"\n"), "recovery-wrong-identity"),
		pass("commits seq in the header changed", recReplace(t, pt, "commits 2 ", "commits 3 "), "recovery-wrong-identity"),
		pass("commits digest in the header changed", recReplace(t, pt, hex.EncodeToString(commits.Digest[:]), hex.EncodeToString(d3[:])), "recovery-wrong-identity"),
		pass("hub in the header changed", recReplace(t, pt, "hub "+recHub+"\n", "hub https://other.example\n"), "recovery-wrong-identity"),
		pass("one byte of the ciphertext changed", render(pb, recFlip(pRaw, -1)), "recovery-passphrase"),
		pass("key 6 dropped from the block", render(pb, recMapEdit(t, pRaw, func(m map[uint64]cbor.RawMessage) { delete(m, 6) })), "recovery-format"),
		pass("unregistered key 8 added to the block", render(pb, recMapEdit(t, pRaw, func(m map[uint64]cbor.RawMessage) { m[8] = cbor.RawMessage{0xf6} })), "recovery-format"),
		pass("the block not in canonical form (commits seq in two bytes)", render(pb, nonCanon), "recovery-format"),
		pass("argon2id t changed to 4", render(pb, tRaw), "recovery-format"),
		pass("commits not derived from the sealed seed", render(&wcBlob, wrongCommits), "recovery-format"),
		pass("the local file opened with the passphrase interface", lt, "recovery-unprotected"),
		local("the passphrase file opened with the local-key interface", pt, lk[:], "recovery-format"),
		local("the passphrase file opened with the local-key interface and its own argon2id key", pt, key, "recovery-format"),
		local("the passphrase block relabelled local, opened with its own argon2id key", render(&relabelled, relRaw), key, "recovery-format"),
		local("wrong local key", lt, wrongLocal, "recovery-format"),
		local("one byte of the local ciphertext changed", render(&lf.blob, recFlip(lRaw, -1)), lk[:], "recovery-format"),
	}
	v.DeriveNegatives = []recDeriveNegative{
		{Name: "AID holding U+0000", AID: aid[:8] + "\x00" + aid[8:], Seq: 2, Error: "next-key-input"},
		{Name: "empty AID", AID: "", Seq: 2, Error: "next-key-input"},
	}
	return encodeVector(t, v)
}

// The committed RECOVERY-1 is what this implementation generates.
func TestRECOVERY1Vector(t *testing.T) {
	withCachedKDF(t)
	want := recoveryVectorFile(t)
	path := filepath.Join("testdata", "vec-recovery-1.json")
	if *updateVectors {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (generate with -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from what Go generates (regenerate with -update and check the diff)", path)
	}
}

// Every value of the committed RECOVERY-1 holds when checked from the file alone: the derivation,
// both files open to rs with their secret and state what they record, every negative fails with
// its class.
func TestRECOVERY1Cases(t *testing.T) {
	withCachedKDF(t)
	var v recoveryVector
	readVector(t, "vec-recovery-1.json", &v)
	var rs [32]byte
	if s := sha256.Sum256([]byte(v.RSLabel)); hex.EncodeToString(s[:]) != v.RS {
		t.Fatal("rs is not SHA-256 of rs_label")
	}
	copy(rs[:], mustHex(t, v.RS))
	if len(v.NextKeys) != 3 {
		t.Fatalf("%d next keys", len(v.NextKeys))
	}
	for _, nk := range v.NextKeys {
		k, err := RecoverySeed(rs, v.AID, nk.Seq)
		if err != nil {
			t.Fatal(err)
		}
		d, err := NextDigest(rs, v.AID, nk.Seq)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(k.Seed()) != nk.Seed || hex.EncodeToString(pubOf(k)) != nk.Pub || hex.EncodeToString(d[:]) != nk.NextDigest {
			t.Errorf("seq %d: derived %x / %x / %x, recorded %+v", nk.Seq, k.Seed(), pubOf(k), d, nk)
		}
	}
	commit := func(c recCommits) Commit {
		out := Commit{Seq: c.Seq}
		copy(out.Digest[:], mustHex(t, c.NextDigest))
		return out
	}
	// the passphrase file
	p := v.PassphraseFile
	got, aid, hub, c, err := OpenRecoveryFile([]byte(p.Text), []byte(p.Passphrase))
	if err != nil || got != rs || aid != v.AID || hub != p.Hub || c != commit(p.Commits) {
		t.Fatalf("passphrase file: %v %s %s %+v", err, aid, hub, c)
	}
	if k := passphraseKey(nfc([]byte(p.Passphrase)), mustHex(t, p.Salt)); hex.EncodeToString(k) != p.Key {
		t.Errorf("argon2id key %x, recorded %s", k, p.Key)
	}
	checkRecBlob(t, "passphrase file", p.Text, p.AAD, p.Blob)
	// the local file
	l := v.LocalFile
	var lk [32]byte
	copy(lk[:], mustHex(t, l.LocalKey))
	got, aid, hub, c, err = OpenRecoveryFileLocal([]byte(l.Text), lk)
	if err != nil || got != rs || aid != v.AID || hub != l.Hub || c != commit(l.Commits) {
		t.Fatalf("local file: %v %s %s %+v", err, aid, hub, c)
	}
	checkRecBlob(t, "local file", l.Text, l.AAD, l.Blob)
	for _, info := range []struct {
		text  string
		unpro bool
	}{{p.Text, false}, {l.Text, true}} {
		fi, err := ParseRecoveryFile([]byte(info.text))
		if err != nil || fi.Unprotected != info.unpro || fi.AID != v.AID || fi.Hub != recHub || fi.Commits != commit(p.Commits) {
			t.Errorf("ParseRecoveryFile: %+v %v", fi, err)
		}
	}
	if len(v.Negatives) == 0 || len(v.DeriveNegatives) == 0 {
		t.Fatal("no negatives")
	}
	for _, n := range v.Negatives {
		want, ok := recErrClass[n.Error]
		if !ok {
			t.Fatalf("%s: unknown class %s", n.Name, n.Error)
		}
		switch n.Open {
		case "passphrase":
			_, _, _, _, err = OpenRecoveryFile([]byte(n.Text), []byte(n.Passphrase))
		case "local":
			var k [32]byte
			copy(k[:], mustHex(t, n.LocalKey))
			_, _, _, _, err = OpenRecoveryFileLocal([]byte(n.Text), k)
		default:
			t.Fatalf("%s: open %q", n.Name, n.Open)
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %s", n.Name, err, n.Error)
		}
	}
	for _, n := range v.DeriveNegatives {
		_, err1 := RecoverySeed(rs, n.AID, n.Seq)
		_, err2 := NextDigest(rs, n.AID, n.Seq)
		if want := recErrClass[n.Error]; !errors.Is(err1, want) || !errors.Is(err2, want) {
			t.Errorf("%s: %v / %v, want %s", n.Name, err1, err2, n.Error)
		}
	}
}

// checkRecBlob: the text's block is the recorded blob, its aad is the recorded aad, and its header
// states what the blob states.
func checkRecBlob(t *testing.T, name, text, aad, blob string) {
	t.Helper()
	f, err := parseRecovery([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := coredet.Marshal(&f.blob)
	a, _ := f.blob.aad()
	if hex.EncodeToString(raw) != blob || hex.EncodeToString(a) != aad {
		t.Errorf("%s: block or aad differs from the record", name)
	}
	if !bytes.Equal(renderRecovery(&f.blob, raw), []byte(text)) {
		t.Errorf("%s: the text is not the rendering of its block", name)
	}
}

func mustHex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// ---- C-30, C-31: next-key derivation ------------------------------------------------------------

func TestRecoverySeedDerivation(t *testing.T) {
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	k2, err := RecoverySeed(rs, aid, 2)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := NextDigest(rs, aid, 2)
	if err != nil {
		t.Fatal(err)
	}
	if d2 != sha256.Sum256(pubOf(k2)) || !bytes.Equal(d2[:], digestOf(k2)) {
		t.Fatal("NextDigest is not SHA-256 of the derived key's public key (KeyEvent key 6)")
	}
	again, _ := RecoverySeed(rs, aid, 2)
	if !bytes.Equal(again, k2) {
		t.Fatal("derivation is not deterministic")
	}
	seen := map[string]string{hex.EncodeToString(k2): "rs aid 2"}
	other := sha256.Sum256([]byte("kel-3 other rs"))
	for name, in := range map[string]struct {
		rs  [32]byte
		aid string
		seq uint64
	}{
		"seq 3": {rs, aid, 3}, "seq 0": {rs, aid, 0}, "seq max": {rs, aid, ^uint64(0)},
		"other rs": {other, aid, 2}, "other aid": {rs, kel2A()[0].EventID, 2},
		// the 0x00 after the AID keeps (aid, seq) pairs apart that would otherwise share bytes
		"aid prefix": {rs, aid[:len(aid)-1], 2},
	} {
		k, err := RecoverySeed(in.rs, in.aid, in.seq)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if prev, dup := seen[hex.EncodeToString(k)]; dup {
			t.Errorf("%s derives the same key as %s", name, prev)
		}
		seen[hex.EncodeToString(k)] = name
	}
	// CORE-E9 and the other refusals
	for name, bad := range map[string]string{"NUL": "a\x00b", "NUL first": "\x00", "empty": "", "not UTF-8": "a\xffb"} {
		if _, err := RecoverySeed(rs, bad, 2); !errors.Is(err, ErrNextKeyInput) {
			t.Errorf("%s AID: %v", name, err)
		}
		if _, err := NextDigest(rs, bad, 2); !errors.Is(err, ErrNextKeyInput) {
			t.Errorf("%s AID, NextDigest: %v", name, err)
		}
	}
	if _, err := RecoverySeed([32]byte{}, aid, 2); !errors.Is(err, ErrNextKeyInput) {
		t.Errorf("all-zero seed: %v", err)
	}
}

// C-30, C-31 and D-16 in a KEL: the icp commits the hot k1, the witness rot reveals it and commits
// next_digest(aid, 2) from RS, and from then on every rot reveals key(aid, j) and commits
// next_digest(aid, j+1); a change of seed (protect, --new-recovery) is a rot that reveals the old
// seed's key and commits the new seed's, and the next rot reveals the new seed's key. The KEL
// replays; a key derived for the wrong seq or from the wrong seed does not.
func TestRecoverySeedDrivesTheKEL(t *testing.T) {
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	rs2 := sha256.Sum256([]byte("kel-3 test rs, the new seed"))
	k := vecKeys("KEL-2B")
	w := kel2A()[0].EventID
	kel := []SignedEvent{signEvent(icpEvent(k[0], k[1], agentT0, ToadAgent), k[0])}
	aid := kel[0].EventID
	rot := func(rev ed25519.PrivateKey, next [32]byte, ts uint64) KeyEvent {
		return KeyEvent{KELType: KELType, Type: Rotation, Keys: [][]byte{pubOf(rev)}, NextDigest: next[:], Threshold: 1,
			Timestamp: ts, Toad: ToadField(ToadAgent), Witnesses: []string{w}}
	}
	seed := func(rs [32]byte, seq uint64) ed25519.PrivateKey {
		k, err := RecoverySeed(rs, aid, seq)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	kel = extend(kel, rot(k[1], mustDigest(t, rs, aid, 2), agentT0+minute), k[1])                  // seq 1: witness rot
	kel = extend(kel, rot(seed(rs, 2), mustDigest(t, rs, aid, 3), agentT0+2*minute), seed(rs, 2))  // seq 2: scheduled
	kel = extend(kel, rot(seed(rs, 3), mustDigest(t, rs2, aid, 4), agentT0+3*minute), seed(rs, 3)) // seq 3: to RS′
	good := extend(kel, rot(seed(rs2, 4), mustDigest(t, rs2, aid, 5), agentT0+4*minute), seed(rs2, 4))
	good = extend(good, dipEvent(seed(rs2, 5), agentT0+5*minute), seed(rs2, 5))
	if _, err := Replay(good); err != nil {
		t.Fatalf("a KEL driven by the recovery seeds: %v", err)
	}
	for name, rev := range map[string]ed25519.PrivateKey{"old seed after the change": seed(rs, 4), "wrong seq": seed(rs2, 5)} {
		bad := extend(kel, rot(rev, mustDigest(t, rs2, aid, 5), agentT0+4*minute), rev)
		if _, err := Replay(bad); err == nil {
			t.Errorf("%s: replayed", name)
		}
	}
}

// ---- C-34: passphrases --------------------------------------------------------------------------

func TestPassphraseLengthBoundary(t *testing.T) {
	cases := []struct {
		name string
		p    string
		ok   bool
	}{
		{"11 ASCII", strings.Repeat("a", 11), false},
		{"12 ASCII", strings.Repeat("a", 12), true},
		{"11 CJK (33 bytes)", strings.Repeat("钥", 11), false},
		{"12 CJK", strings.Repeat("钥", 12), true},
		// e + U+0301 is 12 code points as typed, 6 after NFC
		{"6 composed pairs", strings.Repeat("e\u0301", 6), false},
		{"11 composed + 1", strings.Repeat("e\u0301", 11) + "x", true},
		{"empty", "", false},
	}
	withFastKDF(t)
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	c := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	for _, tc := range cases {
		err := CheckPassphrase([]byte(tc.p))
		_, serr := SealRecoveryFile(rs, aid, "", c, []byte(tc.p))
		if tc.ok && (err != nil || serr != nil) || !tc.ok && (!errors.Is(err, ErrPassphraseTooShort) || !errors.Is(serr, ErrPassphraseTooShort)) {
			t.Errorf("%s: CheckPassphrase %v, Seal %v", tc.name, err, serr)
		}
	}
}

// The passphrase is normalized to NFC, not NFKC: the same text typed composed or decomposed opens
// the file; a compatibility variant does not.
func TestPassphraseNFC(t *testing.T) {
	withFastKDF(t)
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	c := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	composed := "caf\u00e9 au lait, s'il vous pla\u00eet"
	decomposed := "cafe\u0301 au lait, s'il vous plai\u0302t"
	file, err := SealRecoveryFile(rs, aid, recHub, c, []byte(composed))
	if err != nil {
		t.Fatal(err)
	}
	if got, _, _, _, err := OpenRecoveryFile(file, []byte(decomposed)); err != nil || got != rs {
		t.Fatalf("decomposed form: %v", err)
	}
	file2, err := SealRecoveryFile(rs, aid, recHub, c, []byte(decomposed))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := OpenRecoveryFile(file2, []byte(composed)); err != nil {
		t.Fatalf("composed form against a decomposed seal: %v", err)
	}
	if _, _, _, _, err := OpenRecoveryFile(file, []byte("caf\u00e9 au lait, s'il vous pla\u00eet\uff01")); !errors.Is(err, ErrRecoveryPassphrase) {
		t.Fatalf("another passphrase: %v", err)
	}
	full := "\uff41\uff4e\uff45\uff54 passphrase" // fullwidth "anet": equal under NFKC, not under NFC
	file3, err := SealRecoveryFile(rs, aid, recHub, c, []byte("anet passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := OpenRecoveryFile(file3, []byte(full)); !errors.Is(err, ErrRecoveryPassphrase) {
		t.Fatalf("an NFKC variant opened the file: %v", err)
	}
	// the caller's buffer is not cleared or changed by normalization
	buf := []byte(composed)
	if _, err := SealRecoveryFile(rs, aid, "", c, buf); err != nil || string(buf) != composed {
		t.Fatalf("the passphrase buffer changed: %q %v", buf, err)
	}
}

// ---- C-35, C-36: sealing and opening -----------------------------------------------------------

// The real argon2id path, end to end, and a fresh salt and nonce every time.
func TestRecoveryFileRealKDF(t *testing.T) {
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	c := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	pass := []byte("correct horse battery staple")
	a, err := SealRecoveryFile(rs, aid, recHub, c, pass)
	if err != nil {
		t.Fatal(err)
	}
	got, gaid, ghub, gc, err := OpenRecoveryFile(a, pass)
	if err != nil || got != rs || gaid != aid || ghub != recHub || gc != c {
		t.Fatalf("round trip: %v", err)
	}
	if _, _, _, _, err := OpenRecoveryFile(a, []byte("correct horse battery stapler")); !errors.Is(err, ErrRecoveryPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	withFastKDF(t)
	b, err := SealRecoveryFile(rs, aid, recHub, c, pass)
	if err != nil {
		t.Fatal(err)
	}
	fa, _ := parseRecovery(a)
	fb, _ := parseRecovery(b)
	if bytes.Equal(fa.blob.KDF.Salt, fb.blob.KDF.Salt) || bytes.Equal(fa.blob.Nonce, fb.blob.Nonce) || bytes.Equal(fa.blob.CT, fb.blob.CT) {
		t.Fatal("two seals share a salt, a nonce or a ciphertext")
	}
	var lk [32]byte
	copy(lk[:], recSeed("local-key"))
	l1, _ := SealRecoveryFileLocal(rs, aid, recHub, c, lk)
	l2, _ := SealRecoveryFileLocal(rs, aid, recHub, c, lk)
	f1, _ := parseRecovery(l1)
	f2, _ := parseRecovery(l2)
	if bytes.Equal(f1.blob.Nonce, f2.blob.Nonce) {
		t.Fatal("two local seals share a nonce")
	}
}

// P7: a random seed round-trips under a random passphrase and under a random local key; every
// single bit flipped in the block makes it fail to open (or to parse); neither mode's block opens
// through the other mode's interface.
func TestRecoveryP7(t *testing.T) {
	withFastKDF(t)
	rng := rand.New(rand.NewSource(7))
	alphabet := []rune("abcXYZ019 -_.,!\u5bc6\u94a5\u6062\u590d\u53e3\u4ee4\u00e9\u00fc\u00df\u03a9\u0436\u0301\u0302\uff71\U0001f600")
	aid := kel2B()[0].EventID
	for round := 0; round < 6; round++ {
		var rs, lk [32]byte
		rng.Read(rs[:])
		rng.Read(lk[:])
		var p []rune
		for len(p) < 12+rng.Intn(20) {
			p = append(p, alphabet[rng.Intn(len(alphabet))])
		}
		pass := []byte(string(p))
		for CheckPassphrase(pass) != nil {
			pass = append(pass, 'x')
		}
		seq := 1 + uint64(rng.Intn(1000))
		c := Commit{Seq: seq, Digest: mustDigest(t, rs, aid, seq)}
		hub := []string{"", recHub, "https://hub.example:8443/anet"}[round%3]
		pt, err := SealRecoveryFile(rs, aid, hub, c, pass)
		if err != nil {
			t.Fatal(err)
		}
		lt, err := SealRecoveryFileLocal(rs, aid, hub, c, lk)
		if err != nil {
			t.Fatal(err)
		}
		if got, gaid, ghub, gc, err := OpenRecoveryFile(pt, pass); err != nil || got != rs || gaid != aid || ghub != hub || gc != c {
			t.Fatalf("round %d passphrase: %v", round, err)
		}
		if got, gaid, ghub, gc, err := OpenRecoveryFileLocal(lt, lk); err != nil || got != rs || gaid != aid || ghub != hub || gc != c {
			t.Fatalf("round %d local: %v", round, err)
		}
		if _, _, _, _, err := OpenRecoveryFile(lt, pass); !errors.Is(err, ErrRecoveryUnprotected) {
			t.Fatalf("local block through the passphrase interface: %v", err)
		}
		pkey := passphraseKey(nfc(pass), mustParse(t, pt).blob.KDF.Salt)
		var asLocal [32]byte
		copy(asLocal[:], pkey)
		for _, k := range [][32]byte{lk, asLocal} {
			if _, _, _, _, err := OpenRecoveryFileLocal(pt, k); !errors.Is(err, ErrRecoveryFormat) {
				t.Fatalf("passphrase block through the local interface: %v", err)
			}
		}
		for _, m := range []struct {
			name string
			text []byte
			open func([]byte) error
		}{
			{"passphrase", pt, func(b []byte) error { _, _, _, _, err := OpenRecoveryFile(b, pass); return err }},
			{"local", lt, func(b []byte) error { _, _, _, _, err := OpenRecoveryFileLocal(b, lk); return err }},
		} {
			f := mustParse(t, m.text)
			raw, _ := coredet.Marshal(&f.blob)
			for bit := 0; bit < 8*len(raw); bit++ {
				flipped := bytes.Clone(raw)
				flipped[bit/8] ^= 1 << (bit % 8)
				if err := m.open(renderRecovery(&f.blob, flipped)); err == nil {
					t.Fatalf("round %d %s: bit %d flipped in the block, and the file opened", round, m.name, bit)
				}
			}
		}
	}
}

// nonZeroPadBits returns text with the last character of its base64 block changed in its padding
// bits only: a lenient decoder reads the same block from it, a strict one refuses it.
func nonZeroPadBits(tb testing.TB, text string) string {
	tb.Helper()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	lines := strings.Split(text, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimRight(lines[i], "=")
		if pad := len(lines[i]) - len(l); pad > 0 && l != "" {
			j := strings.IndexByte(alphabet, l[len(l)-1])
			lines[i] = l[:len(l)-1] + string(alphabet[j^1]) + strings.Repeat("=", pad)
			out := strings.Join(lines, "\n")
			a, errA := blockOf(text)
			b, errB := blockOf(out)
			if errA != nil || errB != nil || !bytes.Equal(a, b) {
				tb.Fatalf("the padding-bit edit changed the block: %v %v", errA, errB)
			}
			return out
		}
	}
	tb.Fatal("the block has no padding")
	return ""
}

func mustParse(tb testing.TB, b []byte) *recoveryFile {
	tb.Helper()
	f, err := parseRecovery(b)
	if err != nil {
		tb.Fatal(err)
	}
	return f
}

// C-33, C-37: the header must state what the block states; the block is the authority.
func TestRecoveryHeaderMustMatchTheBlock(t *testing.T) {
	withFastKDF(t)
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	c := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	pass := []byte("a passphrase of some length")
	var lk [32]byte
	copy(lk[:], recSeed("local-key"))
	pt, _ := SealRecoveryFile(rs, aid, recHub, c, pass)
	lt, _ := SealRecoveryFileLocal(rs, aid, recHub, c, lk)
	d := hex.EncodeToString(c.Digest[:])
	d3 := mustDigest(t, rs, aid, 3)
	for _, file := range []string{string(pt), string(lt)} {
		for name, edit := range map[string][2]string{
			"AID":            {"AID " + aid + "\n", "AID " + kel2A()[0].EventID + "\n"},
			"AID one letter": {"AID " + aid + "\n", "AID " + aid[:len(aid)-1] + "a\n"},
			"commits seq":    {"commits 2 ", "commits 3 "},
			"commits digest": {d, hex.EncodeToString(d3[:])},
			"hub":            {"hub " + recHub + "\n", "hub https://other.example\n"},
		} {
			bad := recReplace(t, file, edit[0], edit[1])
			if _, err := ParseRecoveryFile([]byte(bad)); !errors.Is(err, ErrRecoveryWrongIdentity) {
				t.Errorf("%s changed: %v", name, err)
			}
			if _, _, _, _, err := OpenRecoveryFile([]byte(bad), pass); !errors.Is(err, ErrRecoveryWrongIdentity) {
				t.Errorf("%s changed, OpenRecoveryFile: %v", name, err)
			}
			if _, _, _, _, err := OpenRecoveryFileLocal([]byte(bad), lk); !errors.Is(err, ErrRecoveryWrongIdentity) {
				t.Errorf("%s changed, OpenRecoveryFileLocal: %v", name, err)
			}
		}
		// the hub line is a hint and may be missing
		noHub := recReplace(t, file, "hub "+recHub+"\n", "")
		if fi, err := ParseRecoveryFile([]byte(noHub)); err != nil || fi.Hub != recHub {
			t.Errorf("without the hub line: %+v %v", fi, err)
		}
		// a malformed header is not a recovery file
		for name, edit := range map[string][2]string{
			"first line":      {"anet-recovery v1\n", "anet-recovery v2\n"},
			"AID missing":     {"AID " + aid + "\n", ""},
			"commits missing": {"commits 2 " + d + "\n", ""},
			"AID twice":       {"AID " + aid + "\n", "AID " + aid + "\nAID " + aid + "\n"},
			"unknown line":    {"AID " + aid + "\n", "AID " + aid + "\nname x\n"},
			"commits seq 02":  {"commits 2 ", "commits 02 "},
			"commits +2":      {"commits 2 ", "commits +2 "},
			"upper-case hex":  {d, strings.ToUpper(d)},
			"short digest":    {d, d[:62]},
			"no blank line":   {"\n\n", "\n"},
		} {
			bad := recReplace(t, file, edit[0], edit[1])
			if _, err := ParseRecoveryFile([]byte(bad)); !errors.Is(err, ErrRecoveryFormat) {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
	// a hub-less file has no hub line
	nh, err := SealRecoveryFile(rs, aid, "", c, pass)
	if err != nil || strings.Contains(string(nh), "\nhub ") {
		t.Fatalf("hub-less file: %v\n%s", err, nh)
	}
	if fi, err := ParseRecoveryFile(nh); err != nil || fi.Hub != "" {
		t.Fatalf("hub-less file: %+v %v", fi, err)
	}
	// ...but its block still carries key 5, as "" (core §2.6: every key of RecoveryBlob is required)
	nhRaw, err := blockOf(string(nh))
	if err != nil {
		t.Fatal(err)
	}
	nhMap := map[uint64]cbor.RawMessage{}
	if err := coredet.Unmarshal(nhRaw, &nhMap); err != nil {
		t.Fatal(err)
	}
	if v, ok := nhMap[5]; !ok || !bytes.Equal(v, []byte{0x60}) {
		t.Fatalf("a hub-less block: key 5 is %x (present %v), want the empty text string", v, ok)
	}
	if _, err := ParseRecoveryFile([]byte(strings.Replace(string(nh), "\ncommits ", "\nhub "+recHub+"\ncommits ", 1))); !errors.Is(err, ErrRecoveryWrongIdentity) {
		t.Fatalf("a hub line added to a hub-less file: %v", err)
	}
}

// The text form: what Seal writes, what WithRecoveryNote adds, what a copy may gain on the way.
func TestRecoveryText(t *testing.T) {
	withFastKDF(t)
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	c := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	pass := []byte("a passphrase of some length")
	file, err := SealRecoveryFile(rs, aid, recHub, c, pass)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(file), "\n"), "\n")
	want := []string{"anet-recovery v1", "AID " + aid, "hub " + recHub, fmt.Sprintf("commits 2 %x", c.Digest), ""}
	if !reflect.DeepEqual(lines[:5], want) {
		t.Fatalf("header %q", lines[:5])
	}
	for i, l := range lines[5:] {
		if l == "" || len(l) > recoveryBase64Line || i < len(lines)-6 && len(l) != recoveryBase64Line {
			t.Fatalf("block line %d: %q", i, l)
		}
	}
	noted, err := WithRecoveryNote(file, "这份文件加上你的口令,可以轮换、恢复或注销这个身份。", "With your passphrase, this file can rotate, recover or deactivate this identity.")
	if err != nil {
		t.Fatal(err)
	}
	if want := string(file) + "\n这份文件加上你的口令,可以轮换、恢复或注销这个身份。\nWith your passphrase, this file can rotate, recover or deactivate this identity.\n"; string(noted) != want {
		t.Fatalf("noted file:\n%s", noted)
	}
	if _, err := WithRecoveryNote(noted, "again"); err == nil {
		t.Fatal("a second note was added")
	}
	for _, bad := range [][]string{{}, {""}, {"two\nlines"}, {"a\rb"}, {"\x00"}, {strings.Repeat("x", maxRecoveryFileLen)}} {
		if _, err := WithRecoveryNote(file, bad...); err == nil {
			t.Errorf("note %.40q accepted", bad)
		}
	}
	// a file that lost its final line end would take the note into its block: refused, not written
	if _, err := WithRecoveryNote(bytes.TrimSuffix(file, []byte("\n")), "a note"); err == nil {
		t.Error("a note was added to a file without its final line end")
	}
	crlf := strings.ReplaceAll(string(noted), "\n", "\r\n")
	for name, text := range map[string]string{"as written": string(file), "noted": string(noted), "CRLF": crlf, "BOM": "\ufeff" + string(noted), "no final newline": strings.TrimSuffix(string(file), "\n")} {
		if got, _, _, _, err := OpenRecoveryFile([]byte(text), pass); err != nil || got != rs {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, text := range map[string]string{
		"empty":                   "",
		"header only":             "anet-recovery v1\nAID " + aid + "\ncommits 2 " + hex.EncodeToString(c.Digest[:]) + "\n",
		"not base64":              strings.Replace(string(file), "\n\n", "\n\n*", 1),
		"base64 padding bits set": nonZeroPadBits(t, string(file)),
		"not UTF-8":               string(file) + "\n\xff\n",
		"too large":               string(file) + "\n" + strings.Repeat("x", maxRecoveryFileLen) + "\n",
		"block split":             strings.Replace(string(file), "\n\n", "\n\n"+strings.Split(string(file), "\n")[5]+"\n\n", 1),
	} {
		if _, err := ParseRecoveryFile([]byte(text)); !errors.Is(err, ErrRecoveryFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// What Seal refuses to write.
func TestSealRefuses(t *testing.T) {
	withFastKDF(t)
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	c := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	pass := []byte("a passphrase of some length")
	var lk [32]byte
	copy(lk[:], recSeed("local-key"))
	c3 := Commit{Seq: 3, Digest: c.Digest}
	other := Commit{Seq: 2, Digest: mustDigest(t, sha256.Sum256([]byte("other")), aid, 2)}
	// commitsOf is what rs commits to at seq 2 for a, so that an AID the header cannot carry is
	// refused for itself and not because commits were derived for another AID.
	commitsOf := func(a string) Commit {
		if d, err := NextDigest(rs, a, 2); err == nil {
			return Commit{Seq: 2, Digest: d}
		}
		return c
	}
	for name, in := range map[string]struct {
		rs  [32]byte
		aid string
		hub string
		c   Commit
	}{
		"commits of another seq":   {rs, aid, "", c3},
		"commits of another seed":  {rs, aid, "", other},
		"AID with a space":         {rs, "bafy x", "", commitsOf("bafy x")},
		"AID with a newline":       {rs, aid + "\nhub x", "", commitsOf(aid + "\nhub x")},
		"AID with a tab":           {rs, "bafy\tx", "", commitsOf("bafy\tx")},
		"AID with a byte-order mk": {rs, "\ufeff" + aid, "", commitsOf("\ufeff" + aid)},
		"AID with U+0000":          {rs, "a\x00b", "", c},
		"empty AID":                {rs, "", "", c},
		"hub with a newline":       {rs, aid, recHub + "\nAID x", c},
		"hub with a space":         {rs, aid, "https://hub.example/a b", c},
		"hub too long":             {rs, aid, "https://" + strings.Repeat("h", maxRecoveryHubLen), c},
		"zero seed":                {[32]byte{}, aid, "", c},
		"hub not UTF-8":            {rs, aid, "https://\xff", c},
		"hub with a byte-order mk": {rs, aid, "\ufeffhttps://hub.example", c},
	} {
		if _, err := SealRecoveryFile(in.rs, in.aid, in.hub, in.c, pass); err == nil {
			t.Errorf("%s: SealRecoveryFile wrote it", name)
		}
		if _, err := SealRecoveryFileLocal(in.rs, in.aid, in.hub, in.c, lk); err == nil {
			t.Errorf("%s: SealRecoveryFileLocal wrote it", name)
		}
	}
	if _, err := SealRecoveryFileLocal(rs, aid, "", c, [32]byte{}); err == nil {
		t.Error("an all-zero local key was used")
	}
	file, _ := SealRecoveryFileLocal(rs, aid, "", c, lk)
	if _, _, _, _, err := OpenRecoveryFileLocal(file, [32]byte{}); !errors.Is(err, ErrRecoveryFormat) {
		t.Errorf("an all-zero local key: %v", err)
	}
	// a block that was sealed under the all-zero key still does not open with it
	zb, zraw := recBlob(t, aid, "", recoveryKDF{Alg: kdfLocal}, recSeed("nonce")[:recoveryNonce], c, make([]byte, 32), rs)
	if _, _, _, _, err := OpenRecoveryFileLocal(renderRecovery(zb, zraw), [32]byte{}); !errors.Is(err, ErrRecoveryFormat) {
		t.Errorf("a block sealed under the all-zero local key: %v", err)
	}
	// the salt and nonce sizes are checked before anything is sealed (no panic in the AEAD)
	if _, err := sealRecoveryPassphrase(rs, aid, "", c, pass, make([]byte, recoverySalt-1), make([]byte, recoveryNonce)); err == nil {
		t.Error("a 15-byte salt was used")
	}
	if _, err := sealRecoveryLocal(rs, aid, "", c, lk, make([]byte, 12)); err == nil {
		t.Error("a 12-byte nonce was used")
	}
}

// Every key of the block is checked when a file is read (core \u00a72.6, C-33), not left to the AEAD:
// each block below is sealed so that its ciphertext opens under the key given, and only the check
// of the key it breaks refuses it. All three readers refuse it as ErrRecoveryFormat, without a
// panic, before any secret is used.
func TestRecoveryBlockKeysAreChecked(t *testing.T) {
	withFastKDF(t)
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	c := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	pass := []byte("a passphrase of some length")
	salt := recSeed("salt")[:recoverySalt]
	nonce := recSeed("nonce")[:recoveryNonce]
	var lk [32]byte
	copy(lk[:], recSeed("local-key"))
	argon := recoveryKDF{Alg: kdfArgon2id, T: argon2Time, MKiB: argon2MemKiB, P: argon2Lanes, Salt: salt}
	setAID := func(b *recoveryBlob, a string) {
		b.AID = a
		if d, err := NextDigest(rs, a, 2); err == nil {
			b.Commits.Digest = d[:]
		}
	}
	cases := []struct {
		name string
		edit func(b *recoveryBlob)
		pt   []byte // what is sealed; rs when nil
		ct   func(ct []byte) []byte
	}{
		{name: "key 0: another type tag", edit: func(b *recoveryBlob) { b.Type = "anet.recovery/2" }},
		{name: "key 1: an AID with a space", edit: func(b *recoveryBlob) { setAID(b, "bafy x") }},
		{name: "key 1: an AID holding U+0000", edit: func(b *recoveryBlob) { setAID(b, "bafy\x00x") }},
		{name: "key 1: an AID with a byte-order mark", edit: func(b *recoveryBlob) { setAID(b, "\ufeff"+aid) }},
		{name: "key 2: argon2id t = 4", edit: func(b *recoveryBlob) { b.KDF.T = 4 }},
		{name: "key 2: argon2id m = 1 GiB", edit: func(b *recoveryBlob) { b.KDF.MKiB = 1 << 20 }},
		{name: "key 2: argon2id m = 8 KiB", edit: func(b *recoveryBlob) { b.KDF.MKiB = 8 }},
		{name: "key 2: argon2id p = 1", edit: func(b *recoveryBlob) { b.KDF.P = 1 }},
		{name: "key 2: a 15-byte salt", edit: func(b *recoveryBlob) { b.KDF.Salt = salt[:15] }},
		{name: "key 2: a 17-byte salt", edit: func(b *recoveryBlob) { b.KDF.Salt = append(bytes.Clone(salt), 0) }},
		{name: "key 2: another algorithm", edit: func(b *recoveryBlob) { b.KDF.Alg = "scrypt" }},
		{name: "key 2: local with t", edit: func(b *recoveryBlob) { b.KDF = recoveryKDF{Alg: kdfLocal, T: argon2Time} }},
		{name: "key 2: local with a salt", edit: func(b *recoveryBlob) { b.KDF = recoveryKDF{Alg: kdfLocal, Salt: salt} }},
		{name: "key 3: another AEAD", edit: func(b *recoveryBlob) { b.AEAD = "chacha20poly1305" }},
		{name: "key 4: a 12-byte nonce", edit: func(b *recoveryBlob) { b.Nonce = nonce[:12] }},
		{name: "key 4: a 25-byte nonce", edit: func(b *recoveryBlob) { b.Nonce = append(bytes.Clone(nonce), 0) }},
		{name: "key 5: a hub hint with a space", edit: func(b *recoveryBlob) { b.Hub = "https://hub.example/a b" }},
		{name: "key 5: a hub hint holding U+0000", edit: func(b *recoveryBlob) { b.Hub = "https://hub.example/\x00" }},
		{name: "key 5: a hub hint over 2048 bytes", edit: func(b *recoveryBlob) { b.Hub = "https://" + strings.Repeat("h", maxRecoveryHubLen) }},
		{name: "key 6: a 31-byte digest", edit: func(b *recoveryBlob) { b.Commits.Digest = c.Digest[:31] }},
		{name: "key 6: a 33-byte digest", edit: func(b *recoveryBlob) { b.Commits.Digest = append(bytes.Clone(c.Digest[:]), 0) }},
		{name: "key 7: a sealed 31-byte seed", pt: rs[:31]},
		{name: "key 7: a sealed 33-byte seed", pt: append(bytes.Clone(rs[:]), 0)},
		{name: "key 7: one byte short", ct: func(ct []byte) []byte { return ct[:len(ct)-1] }},
		{name: "key 7: missing", ct: func([]byte) []byte { return nil }},
	}
	for _, kdf := range []recoveryKDF{argon, {Alg: kdfLocal}} {
		for _, tc := range cases {
			name := kdf.Alg + ", " + tc.name
			b := recoveryBlob{Type: recoveryType, AID: aid, KDF: kdf, AEAD: recoveryAEAD, Nonce: bytes.Clone(nonce), Hub: recHub,
				Commits: recoveryCommits{Seq: c.Seq, Digest: bytes.Clone(c.Digest[:])}}
			if tc.edit != nil {
				tc.edit(&b)
			}
			key := lk[:]
			if b.KDF.Alg != kdfLocal {
				key = passphraseKey(nfc(pass), b.KDF.Salt)
			}
			aad, err := b.aad()
			if err != nil {
				t.Fatal(err)
			}
			n := b.Nonce
			if len(n) != recoveryNonce {
				n = nonce // the AEAD needs 24 bytes; the block states the other length
			}
			pt := tc.pt
			if pt == nil {
				pt = rs[:]
			}
			a, err := chacha20poly1305.NewX(key)
			if err != nil {
				t.Fatal(err)
			}
			b.CT = a.Seal(nil, n, pt, aad)
			if tc.ct != nil {
				b.CT = tc.ct(b.CT)
			}
			raw, err := coredet.Marshal(&b)
			if err != nil {
				t.Fatal(err)
			}
			text := string(renderRecovery(&b, raw))
			if len(b.Commits.Digest) != sha256.Size {
				// the header can only state a 32-byte digest; it states the one the block nearly has
				text = recReplace(t, text, fmt.Sprintf("commits %d %x\n", c.Seq, b.Commits.Digest), fmt.Sprintf("commits %d %x\n", c.Seq, c.Digest))
			}
			for reader, read := range map[string]func() error{
				"ParseRecoveryFile":     func() error { _, err := ParseRecoveryFile([]byte(text)); return err },
				"OpenRecoveryFile":      func() error { _, _, _, _, err := OpenRecoveryFile([]byte(text), pass); return err },
				"OpenRecoveryFileLocal": func() error { _, _, _, _, err := OpenRecoveryFileLocal([]byte(text), lk); return err },
			} {
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("%s: %s panicked: %v", name, reader, r)
						}
					}()
					if err := read(); !errors.Is(err, ErrRecoveryFormat) {
						t.Errorf("%s: %s gave %v, want ErrRecoveryFormat", name, reader, err)
					}
				}()
			}
		}
	}
}

// ---- SI-38, C-35: who may open a recovery file --------------------------------------------------

// recoveryScope is where OpenRecoveryFile, RecoverySeed and the two *Local functions may be named
// outside this package: "<repository>:<package directory>" (C-35, SI-38). The daemon, and
// everything else, must never hold a recovery seed; only the anet CLI handles the file that has
// no passphrase yet.
var recoveryScope = map[string][]string{
	"OpenRecoveryFile":      {"ANet:cmd/anet", "ANetHub:cmd/anet-hub"},
	"RecoverySeed":          {"ANet:cmd/anet", "ANetHub:cmd/anet-hub"},
	"OpenRecoveryFileLocal": {"ANet:cmd/anet"},
	"SealRecoveryFileLocal": {"ANet:cmd/anet"},
}

const identityImport = "github.com/ANetResearch/ANetCore/identity"

// recoveryScopeProblems lists every reference to a scoped function in the non-test Go files of
// repo (rooted at fsys) made from a package directory its scope does not name.
func recoveryScopeProblems(repo string, fsys fs.FS) ([]string, error) {
	var out []string
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != "." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" || name == "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		src, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("%s:%s: %v", repo, p, err)
		}
		dir := filepath.ToSlash(filepath.Dir(p))
		local := ""
		for _, im := range f.Imports {
			if path, _ := strconv.Unquote(im.Path.Value); path == identityImport {
				local = "identity"
				if im.Name != nil {
					local = im.Name.Name
				}
			}
		}
		if local == "." {
			out = append(out, fmt.Sprintf("%s:%s dot-imports identity; import it by name so the recovery scope can be checked", repo, p))
			return nil
		}
		inIdentity := repo == "ANetCore" && dir == "identity"
		ast.Inspect(f, func(n ast.Node) bool {
			var fn string
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && local != "" && local != "_" && id.Name == local {
					fn = x.Sel.Name
				}
			case *ast.Ident:
				if inIdentity {
					return true // the package that defines them
				}
			}
			allowed, scoped := recoveryScope[fn]
			if !scoped {
				return true
			}
			for _, a := range allowed {
				if a == repo+":"+dir {
					return true
				}
			}
			out = append(out, fmt.Sprintf("%s:%s: %s refers to identity.%s, which only %s may use (SI-38: only the CLI ever holds a recovery seed)",
				repo, fset.Position(n.Pos()), dir, fn, strings.Join(allowed, " and ")))
			return true
		})
		return nil
	})
	return out, err
}

// siblingRepo finds repository name beside this ANetCore checkout (or under Refs/), by its go.mod
// module line, as golden/index_test.go does.
func siblingRepo(name string) (string, bool) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return "", false
	}
	for _, d := range []string{filepath.Join(root, name), filepath.Join(root, "Refs", name)} {
		b, err := os.ReadFile(filepath.Join(d, "go.mod"))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(l) == "module github.com/ANetResearch/"+name {
				return d, true
			}
		}
	}
	return "", false
}

// TestRecoveryAPIScope (C-35, SI-38): OpenRecoveryFile and RecoverySeed are named only from ANet's
// cmd/anet and ANetHub's cmd/anet-hub, OpenRecoveryFileLocal and SealRecoveryFileLocal only from
// cmd/anet,
// in the non-test code of all three repositories. ANet and ANetHub are checked when they sit next
// to this checkout; ANET_GOLDEN_ALL_REPOS=1 makes a missing one a failure.
func TestRecoveryAPIScope(t *testing.T) {
	core, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	roots := map[string]string{"ANetCore": core}
	for _, name := range []string{"ANet", "ANetHub"} {
		if d, ok := siblingRepo(name); ok {
			roots[name] = d
		} else if os.Getenv("ANET_GOLDEN_ALL_REPOS") == "1" {
			t.Errorf("%s is not next to this ANetCore checkout", name)
		} else {
			t.Logf("%s is not next to this ANetCore checkout; its recovery scope is not checked", name)
		}
	}
	for repo, dir := range roots {
		probs, err := recoveryScopeProblems(repo, os.DirFS(dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range probs {
			t.Error(p)
		}
	}
}

// The scope check finds what it must.
func TestRecoveryAPIScopeCatches(t *testing.T) {
	file := func(pkg, imp, body string) []byte {
		return []byte("package " + pkg + "\n\nimport " + imp + "\n\nfunc f() { " + body + " }\n")
	}
	q := strconv.Quote(identityImport)
	for _, tc := range []struct {
		repo, path string
		src        []byte
		bad        bool
	}{
		{"ANet", "internal/daemon/x.go", file("daemon", q, "identity.OpenRecoveryFile(nil, nil)"), true},
		{"ANet", "internal/daemon/x.go", file("daemon", "id "+q, "_ = id.RecoverySeed"), true},
		{"ANet", "internal/daemon/x.go", file("daemon", ". "+q, "_ = 1"), true},
		{"ANet", "cmd/anet/x.go", file("main", q, "identity.OpenRecoveryFileLocal(nil, [32]byte{})"), false},
		{"ANet", "cmd/anet/sub/x.go", file("sub", q, "identity.OpenRecoveryFile(nil, nil)"), true},
		{"ANetHub", "cmd/anet-hub/x.go", file("main", q, "identity.RecoverySeed([32]byte{}, \"\", 0)"), false},
		{"ANetHub", "cmd/anet-hub/x.go", file("main", q, "identity.OpenRecoveryFileLocal(nil, [32]byte{})"), true},
		{"ANetHub", "cmd/anet-hub/x.go", file("main", q, "_ = identity.SealRecoveryFileLocal"), true},
		{"ANetHub", "cmd/anet-hub/x.go", file("main", q, "_ = identity.SealRecoveryFile"), false},
		{"ANet", "internal/daemon/x.go", file("daemon", q, "_ = identity.SealRecoveryFileLocal"), true},
		{"ANetHub", "internal/aghub/x.go", file("aghub", q, "identity.ParseRecoveryFile(nil)"), false},
		{"ANetCore", "seal/x.go", file("seal", q, "identity.RecoverySeed([32]byte{}, \"\", 0)"), true},
		{"ANetCore", "identity/x.go", file("identity", q, "RecoverySeed([32]byte{}, \"\", 0)"), false},
		{"ANet", "internal/daemon/x_test.go", file("daemon", q, "identity.OpenRecoveryFile(nil, nil)"), false},
		{"ANet", "internal/daemon/x.go", file("daemon", "\"other/identity\"", "identity.OpenRecoveryFile(nil, nil)"), false},
	} {
		fsys := fstest.MapFS{tc.path: &fstest.MapFile{Data: tc.src}}
		probs, err := recoveryScopeProblems(tc.repo, fsys)
		if err != nil {
			t.Fatal(err)
		}
		if bad := len(probs) > 0; bad != tc.bad {
			t.Errorf("%s:%s: problems %q, want bad = %v", tc.repo, tc.path, probs, tc.bad)
		}
	}
}

// ---- fuzz: the two new decoders -----------------------------------------------------------------

// recFuzzSeeds are the RECOVERY-1 texts (files and negatives).
func recFuzzSeeds(tb testing.TB) (texts [][]byte, blobs [][]byte) {
	tb.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vec-recovery-1.json"))
	if err != nil {
		tb.Fatal(err)
	}
	var v recoveryVector
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		tb.Fatal(err)
	}
	texts = append(texts, []byte(v.PassphraseFile.Text), []byte(v.LocalFile.Text))
	blobs = append(blobs, mustHex(tb, v.PassphraseFile.Blob), mustHex(tb, v.LocalFile.Blob))
	for _, n := range v.Negatives {
		texts = append(texts, []byte(n.Text))
		if f, err := blockOf(n.Text); err == nil {
			blobs = append(blobs, f)
		}
	}
	return texts, blobs
}

// blockOf returns the decoded base64 block of a recovery text, without checking it.
func blockOf(text string) ([]byte, error) {
	parts := strings.SplitN(text, "\n\n", 3)
	if len(parts) < 2 {
		return nil, errors.New("no block")
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(parts[1], "\n", ""))
}

// FuzzParseRecoveryFile: any bytes, as a recovery file. Nothing panics; a refusal is one of the
// two parse errors; an accepted file renders back to a text that parses to the same thing, and
// opening it gives only the errors its mode allows.
func FuzzParseRecoveryFile(f *testing.F) {
	withFastKDF(f)
	texts, _ := recFuzzSeeds(f)
	for _, t := range texts {
		f.Add(t)
	}
	f.Add([]byte("anet-recovery v1\nAID a\ncommits 2 " + strings.Repeat("0", 64) + "\n\nAA==\n"))
	var lk [32]byte
	copy(lk[:], recSeed("local-key"))
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := ParseRecoveryFile(b)
		if err != nil {
			if !errors.Is(err, ErrRecoveryFormat) && !errors.Is(err, ErrRecoveryWrongIdentity) {
				t.Fatalf("refused with %v", err)
			}
			if _, _, _, _, oerr := OpenRecoveryFileLocal(b, lk); oerr == nil {
				t.Fatal("a file ParseRecoveryFile refuses opened")
			}
			return
		}
		pf, err := parseRecovery(b)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := coredet.Marshal(&pf.blob)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseRecoveryFile(renderRecovery(&pf.blob, raw))
		if err != nil || again != info {
			t.Fatalf("re-rendered: %+v %v, first %+v", again, err, info)
		}
		if strings.IndexFunc(info.AID, notTokenRune) >= 0 || strings.IndexFunc(info.Hub, notTokenRune) >= 0 || !utf8.ValidString(info.AID) {
			t.Fatalf("a field that breaks the header: %+v", info)
		}
		_, _, _, _, perr := OpenRecoveryFile(b, []byte("a passphrase of some length"))
		_, _, _, _, lerr := OpenRecoveryFileLocal(b, lk)
		if info.Unprotected {
			if !errors.Is(perr, ErrRecoveryUnprotected) || lerr != nil && !errors.Is(lerr, ErrRecoveryFormat) {
				t.Fatalf("local file: %v / %v", perr, lerr)
			}
		} else if perr != nil && !errors.Is(perr, ErrRecoveryPassphrase) && !errors.Is(perr, ErrRecoveryFormat) || !errors.Is(lerr, ErrRecoveryFormat) {
			t.Fatalf("passphrase file: %v / %v", perr, lerr)
		}
	})
}

// FuzzRecoveryBlob: any bytes, as the block. Nothing panics; a refusal is ErrRecoveryFormat; an
// accepted block is canonical, and the text rendered from it parses back to the same blob.
func FuzzRecoveryBlob(f *testing.F) {
	_, blobs := recFuzzSeeds(f)
	for _, b := range blobs {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := decodeRecoveryBlob(raw)
		if err != nil {
			if !errors.Is(err, ErrRecoveryFormat) {
				t.Fatalf("refused with %v", err)
			}
			return
		}
		back, err := coredet.Marshal(b)
		if err != nil || !bytes.Equal(back, raw) {
			t.Fatal("an accepted block is not canonical")
		}
		text := renderRecovery(b, raw)
		pf, err := parseRecovery(text)
		if len(text) > maxRecoveryFileLen {
			if !errors.Is(err, ErrRecoveryFormat) {
				t.Fatalf("an oversized text: %v", err)
			}
			return
		}
		if err != nil || !reflect.DeepEqual(pf.blob, *b) {
			t.Fatalf("the rendered text: %v", err)
		}
	})
}
