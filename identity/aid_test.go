package identity

// ValidAID and the witness a rot names (KEL R-3). KEL-2N carries the refused witnesses as vectors.

import (
	"bytes"
	"encoding/base32"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/anetcid"
)

func TestValidAID(t *testing.T) {
	aid := SuiteController().AID()
	raw, err := anetcid.SumRaw([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{aid, SuiteAgentController().AID(), anetcid.MustSum([]byte("any preimage")), testWitness, testOtherHub,
		fuzzWitnesses[0], fuzzWitnesses[1]} {
		if !ValidAID(s) {
			t.Errorf("%q is an AID", s)
		}
	}
	// The last character carries two bits past the 36 bytes; with one of them set, the string
	// decodes to the same bytes but is not their spelling.
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	nonCanonical := []byte(aid)
	last := strings.IndexByte(alphabet, aid[len(aid)-1])
	if last < 0 || last&3 != 0 {
		t.Fatalf("the last character of %q has spare bits set", aid)
	}
	nonCanonical[len(nonCanonical)-1] = alphabet[last|1]
	for name, s := range map[string]string{
		"empty":                       "",
		"the prefix alone":            "bafyrei",
		"a short form":                aid[:20],
		"one character more":          aid + "a",
		"one character less":          aid[:len(aid)-1],
		"upper case":                  strings.ToUpper(aid),
		"another multibase prefix":    "B" + aid[1:],
		"U+0000 inside":               aid[:30] + "\x00" + aid[31:],
		"a newline inside":            aid[:30] + "\n" + aid[31:],
		"a space at the end":          aid[:len(aid)-1] + " ",
		"padding":                     aid[:len(aid)-1] + "=",
		"a CID of the raw codec":      raw,
		"a name":                      "hub.example.org",
		"spare bits of the last char": string(nonCanonical),
		"a non-base32 digit":          aid[:10] + "1" + aid[11:],
	} {
		if ValidAID(s) {
			t.Errorf("%s: %q is not an AID", name, s)
		}
	}
	// Every AID anetcid writes is one; random 59-character strings of the alphabet that decode to
	// another prefix are not.
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		pre := make([]byte, 1+r.Intn(64))
		r.Read(pre)
		if s := anetcid.MustSum(pre); !ValidAID(s) {
			t.Fatalf("anetcid.Sum gave %q, which ValidAID refuses", s)
		}
	}
}

func FuzzValidAID(f *testing.F) {
	f.Add(SuiteController().AID())
	f.Add(testOtherHub)
	f.Add("")
	f.Add("bafyrei")
	f.Fuzz(func(t *testing.T, s string) {
		if !ValidAID(s) {
			return
		}
		// An accepted string is the one spelling of a CIDv1 dag-cbor sha2-256 identifier.
		raw, err := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding).DecodeString(s[1:])
		if err != nil || len(raw) != 36 || !bytes.Equal(raw[:4], []byte{0x01, 0x71, 0x12, 0x20}) || len(s) != 59 || s[0] != 'b' {
			t.Fatalf("ValidAID accepted %q", s)
		}
		if strings.ContainsAny(s, "\x00\n\r =ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Fatalf("ValidAID accepted %q", s)
		}
	})
}

// R-3: the witness a rot names is an AID, whatever builds the rot.
func TestRotWitnessMustBeAnAID(t *testing.T) {
	if errRotWitnessNotAID.Error() != "identity: rot witness is not a valid AID" {
		t.Fatalf("the fixed text of R-3 changed: %q", errRotWitnessNotAID)
	}
	kb := vecKeys("KEL-2B")
	icp := []SignedEvent{signEvent(icpEvent(kb[0], kb[1], agentT0, ToadAgent), kb[0])}
	for _, w := range []string{"", "bafyreiotherhub", testWitness + "\x00", strings.ToUpper(testWitness)} {
		a := SuiteAgentController()
		if _, err := a.BuildWitnessDesignation(w, testNewNext(), SuiteInceptionTS+1); err == nil {
			t.Errorf("a designation of %q was built", w)
		}
		rot := rotEvent(kb[1], kb[2], agentT0+minute, ToadAgent, testWitness, false)
		rot.Witnesses = []string{w}
		if _, err := Replay(extend(icp, rot, kb[1])); !errors.Is(err, errRotWitnessNotAID) {
			t.Errorf("%q: %v", w, err)
		}
	}
	a := SuiteAgentController()
	if _, err := a.BuildWitnessDesignation(testOtherHub, testNewNext(), SuiteInceptionTS+1); err != nil {
		t.Fatalf("an AID: %v", err)
	}
}
