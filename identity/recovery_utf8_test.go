package identity

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// KEL C-34: a passphrase must be valid UTF-8. Bytes typed in a terminal that does not use UTF-8
// could never be typed again in one that does, so the recovery file sealed under them could never
// be opened there. CheckPassphrase and SealRecoveryFile refuse such a passphrase with
// ErrPassphraseNotUTF8 before anything else (a short one too: its next step is another), and
// OpenRecoveryFile says the same rather than that the passphrase is wrong.
func TestCheckPassphraseRefusesInvalidUTF8(t *testing.T) {
	withFastKDF(t)
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	c := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	twelve := "密码短语😀ünïcödé" // 12 code points, 1 to 4 bytes each
	if n := len([]rune(twelve)); n != MinPassphraseRunes {
		t.Fatalf("the valid case has %d code points", n)
	}
	for _, ok := range []string{twelve, strings.Repeat("a", 12), "correct horse battery staple"} {
		if err := CheckPassphrase([]byte(ok)); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
		if _, err := SealRecoveryFile(rs, aid, recHub, c, []byte(ok)); err != nil {
			t.Errorf("%q: Seal: %v", ok, err)
		}
	}
	file, err := SealRecoveryFile(rs, aid, recHub, c, []byte(twelve))
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string][]byte{
		"one byte 0xff after 12 code points": append([]byte(twelve), 0xff),
		"one byte 0xff before them":          append([]byte{0xff}, twelve...),
		"a truncated sequence":               []byte(twelve[:len(twelve)-1]),
		"a lone continuation byte":           append([]byte("aaaaaaaaaaaa"), 0x80),
		"an overlong encoding of /":          append([]byte("aaaaaaaaaaaa"), 0xc0, 0xaf),
		"a UTF-16 surrogate":                 append([]byte("aaaaaaaaaaaa"), 0xed, 0xa0, 0x80),
		"Latin-1 text":                       []byte("caf\xe9 au lait, s'il vous pla\xeet"),
		"short and not UTF-8":                {0xff},
	} {
		if err := CheckPassphrase(p); !errors.Is(err, ErrPassphraseNotUTF8) {
			t.Errorf("%s: CheckPassphrase %v, want ErrPassphraseNotUTF8", name, err)
		}
		if _, err := SealRecoveryFile(rs, aid, recHub, c, p); !errors.Is(err, ErrPassphraseNotUTF8) {
			t.Errorf("%s: SealRecoveryFile %v, want ErrPassphraseNotUTF8", name, err)
		}
		if _, _, _, _, err := OpenRecoveryFile(file, p); !errors.Is(err, ErrPassphraseNotUTF8) {
			t.Errorf("%s: OpenRecoveryFile %v, want ErrPassphraseNotUTF8", name, err)
		}
	}
	// A wrong passphrase that is UTF-8 is still the wrong one.
	if _, _, _, _, err := OpenRecoveryFile(file, []byte(strings.Repeat("b", 12))); !errors.Is(err, ErrRecoveryPassphrase) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
}

// KEL C-33: the AID a recovery file names, in its header and in its block, is an AID by
// ValidAID, the one spelling of it: anything else is ErrRecoveryFormat, before the header is
// compared with the block. A header naming another valid AID than the block is still
// ErrRecoveryWrongIdentity. Sealing for something that is not an AID is refused.
func TestRecoveryHeaderAIDMustBeValid(t *testing.T) {
	withFastKDF(t)
	rs := sha256.Sum256([]byte("kel-3 test rs"))
	aid := kel2B()[0].EventID
	if !ValidAID(aid) {
		t.Fatal("the test AID is not valid")
	}
	c := Commit{Seq: 2, Digest: mustDigest(t, rs, aid, 2)}
	pass := []byte("a passphrase of some length")
	var lk [32]byte
	copy(lk[:], recSeed("local-key"))
	pt, err := SealRecoveryFile(rs, aid, recHub, c, pass)
	if err != nil {
		t.Fatal(err)
	}
	lt, err := SealRecoveryFileLocal(rs, aid, recHub, c, lk)
	if err != nil {
		t.Fatal(err)
	}

	// The last character of an AID carries two spare bits; with one set, it is another spelling
	// of the same 36 bytes, which ValidAID refuses.
	const b32 = "abcdefghijklmnopqrstuvwxyz234567"
	last := strings.IndexByte(b32, aid[len(aid)-1])
	spare := aid[:len(aid)-1] + string(b32[last|1])
	if ValidAID(spare) || spare == aid {
		t.Fatalf("%s is a valid AID", spare)
	}
	invalid := map[string]string{
		"not an AID":               "bafy-not-an-aid",
		"upper case":               strings.ToUpper(aid),
		"spare bits set":           spare,
		"one character short":      aid[:len(aid)-1],
		"a did":                    "did:anet:" + aid,
		"an AID with a trailing x": aid + "x",
	}
	for _, file := range [][]byte{pt, lt} {
		for name, bad := range invalid {
			text := []byte(recReplace(t, string(file), "AID "+aid+"\n", "AID "+bad+"\n"))
			if _, err := ParseRecoveryFile(text); !errors.Is(err, ErrRecoveryFormat) {
				t.Errorf("header %s: ParseRecoveryFile %v, want ErrRecoveryFormat", name, err)
			}
			if _, _, _, _, err := OpenRecoveryFile(text, pass); !errors.Is(err, ErrRecoveryFormat) {
				t.Errorf("header %s: OpenRecoveryFile %v, want ErrRecoveryFormat", name, err)
			}
			if _, _, _, _, err := OpenRecoveryFileLocal(text, lk); !errors.Is(err, ErrRecoveryFormat) {
				t.Errorf("header %s: OpenRecoveryFileLocal %v, want ErrRecoveryFormat", name, err)
			}
		}
		other := []byte(recReplace(t, string(file), "AID "+aid+"\n", "AID "+kel2A()[0].EventID+"\n"))
		if _, err := ParseRecoveryFile(other); !errors.Is(err, ErrRecoveryWrongIdentity) {
			t.Errorf("another valid AID in the header: %v, want ErrRecoveryWrongIdentity", err)
		}
	}
	for name, bad := range invalid {
		if _, err := SealRecoveryFile(rs, bad, recHub, c, pass); err == nil {
			t.Errorf("SealRecoveryFile for %s", name)
		}
		if _, err := SealRecoveryFileLocal(rs, bad, recHub, c, lk); err == nil {
			t.Errorf("SealRecoveryFileLocal for %s", name)
		}
	}
}
