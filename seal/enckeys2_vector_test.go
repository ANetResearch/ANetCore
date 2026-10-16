package seal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ANetResearch/ANetCore/coredet"
	"github.com/ANetResearch/ANetCore/identity"
	"github.com/ANetResearch/ANetCore/identity/identitytest"
)

// ENCKEYS-2 (core §5.2): golden/py/gen_v016.py writes testdata/vec-enckeys-2.json from its own
// implementation of the key set; every value is recomputed here from the same published seeds
// and must agree byte for byte, and every verdict the file states must be this package's.
//
// The owner is a stand-in AID with an Ed25519 identity key and no KEL, so that the vector does
// not move when the KEL format does. The content rules are run on the file's bytes directly; the
// end-to-end check runs VerifyEncKeySet on the same set with the AID of a real identity put in
// its place and signed by that identity, which changes nothing the rules look at.

const ek2File = "testdata/vec-enckeys-2.json"

type ek2Key struct {
	Role      string `json:"role"`
	KID       string `json:"kid"`
	Suite     Suite  `json:"suite"`
	Pub       string `json:"pub"`
	NotBefore uint64 `json:"not_before"`
	NotAfter  uint64 `json:"not_after"`
}

type ek2Entry struct {
	Name   string  `json:"name"`
	Rule   int     `json:"rule"`
	Note   string  `json:"note"`
	Reason *string `json:"reason"`
	Set    string  `json:"set"`
	Sig    string  `json:"sig"`
}

type ek2Vector struct {
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Labels      map[string]string `json:"labels"`
	Seeds       string            `json:"seeds"`
	KEL         string            `json:"kel"`
	EpochMS     uint64            `json:"epoch_ms"`
	FirstEpoch  uint64            `json:"first_epoch"`
	IssuedAt    uint64            `json:"issued_at"`
	AID         struct {
		Role  string `json:"role"`
		Rule  string `json:"rule"`
		Value string `json:"value"`
	} `json:"aid"`
	Identity struct {
		Role        string `json:"role"`
		Public      string `json:"public"`
		KeyStateSeq uint64 `json:"key_state_seq"`
	} `json:"identity"`
	Mbox struct {
		Role  string `json:"role"`
		Epoch uint64 `json:"epoch"`
		Pub   string `json:"pub"`
	} `json:"mbox"`
	Keys        []ek2Key `json:"keys"`
	ExtraKeys   []ek2Key `json:"extra_keys"`
	KIDPreimage string   `json:"kid_preimage"`
	Set         string   `json:"set"`
	Sig         string   `json:"sig"`
	Signed      string   `json:"signed"`
	Verify      []struct {
		Name   string `json:"name"`
		Now    uint64 `json:"now"`
		Result string `json:"result"`
		Select *int   `json:"select"`
	} `json:"verify"`
	Accepted []ek2Entry `json:"accepted"`
	Flipped  struct {
		Note   string `json:"note"`
		Set    string `json:"set"`
		Reason string `json:"reason"`
	} `json:"flipped"`
	Negatives []ek2Entry `json:"negatives"`
}

func ek2Seed(role string) []byte {
	h := sha256.Sum256([]byte("anet-golden/v016/ENCKEYS-2/" + role))
	return h[:]
}

func ek2Hex(t *testing.T, name, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

func ek2Same(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s\n got  %x\n want %s", name, got, want)
	}
}

// ek2Content runs the rules of a key set that do not need the KEL, in VerifyEncKeySet's order.
func ek2Content(b []byte, now uint64) (*EncKeySet, error) {
	s, err := decodeEncKeySet(b)
	if err != nil {
		return nil, err
	}
	if err := s.checkStructure(); err != nil {
		return nil, err
	}
	if err := s.checkValidAt(now); err != nil {
		return nil, err
	}
	return s, nil
}

// ek2Resign puts aid in place of the stand-in AID and signs the result with c.
func ek2Resign(t *testing.T, set []byte, c *identity.Controller) *SignedEncKeySet {
	t.Helper()
	b := rawEdit(t, set, func(m fieldMap) { m[1] = enc(t, c.AID()) })
	sig, seq := c.Sign(b)
	return &SignedEncKeySet{Set: b, KeyStateSeq: seq, Sig: sig}
}

func TestENCKEYS_2(t *testing.T) {
	raw, err := os.ReadFile(ek2File)
	if err != nil {
		t.Fatal(err)
	}
	var v ek2Vector
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.ID != "ENCKEYS-2" || v.Labels["set"] != EncKeySetType || v.Labels["kid"] != kidLabel || v.EpochMS != EpochMS {
		t.Fatalf("header: id %q, labels %v, epoch %d", v.ID, v.Labels, v.EpochMS)
	}

	// The owner, its identity key and its mailbox signing key, from the seeds.
	digest := append([]byte{0x01, 0x71, 0x12, 0x20}, ek2Seed(v.AID.Role)...)
	aid := "b" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest))
	if aid != v.AID.Value {
		t.Fatalf("stand-in aid %s, want %s", aid, v.AID.Value)
	}
	idKey := ed25519.NewKeyFromSeed(ek2Seed(v.Identity.Role))
	idPub := idKey.Public().(ed25519.PublicKey)
	ek2Same(t, "identity public key", idPub, v.Identity.Public)
	signer := func(b []byte) ([]byte, uint64) { return ed25519.Sign(idKey, b), v.Identity.KeyStateSeq }
	mbox := Mbox{Epoch: v.Mbox.Epoch, Pub: ed25519.NewKeyFromSeed(ek2Seed(v.Mbox.Role)).Public().(ed25519.PublicKey)}
	ek2Same(t, "mbox pub", mbox.Pub, v.Mbox.Pub)
	if mbox.Epoch != 1 {
		t.Fatalf("mbox epoch %d", mbox.Epoch)
	}

	// The epoch keys: DeriveKeyPair from the seeds, one per UTC day, and their L15 kids.
	derive := func(rows []ek2Key, first int) []EncKey {
		out := make([]EncKey, len(rows))
		for i, r := range rows {
			e := v.FirstEpoch + uint64(first+i)
			nb, na := e*EpochMS, (e+1)*EpochMS
			if r.NotBefore != nb || r.NotAfter != na {
				t.Fatalf("%s: window [%d, %d), want epoch %d = [%d, %d)", r.Role, r.NotBefore, r.NotAfter, e, nb, na)
			}
			kp, err := DeriveKeyPair(SuiteX25519, ek2Seed(r.Role), nb, na)
			if err != nil {
				t.Fatal(err)
			}
			ek2Same(t, r.Role+" pub", kp.Public.Pub, r.Pub)
			ek2Same(t, r.Role+" kid", kp.Public.KID, r.KID)
			out[i] = kp.Public
		}
		return out
	}
	if len(v.Keys) != 15 || len(v.ExtraKeys) != 18 {
		t.Fatalf("%d keys and %d extra keys, want 15 and 18", len(v.Keys), len(v.ExtraKeys))
	}
	keys := derive(v.Keys, 0)
	extra := derive(v.ExtraKeys, 15)
	pre := append(append([]byte(kidLabel), byte(SuiteX25519)), keys[0].Pub...)
	ek2Same(t, "kid preimage", pre, v.KIDPreimage)
	if h := sha256.Sum256(pre); !bytes.Equal(h[:KIDLen], keys[0].KID) {
		t.Fatal("KID is not the first 16 bytes of SHA-256 over the kid preimage")
	}

	// The set, its L16 signature and the signed form.
	build := func(f func(s *EncKeySet)) EncKeySet {
		s := EncKeySet{Type: EncKeySetType, AID: aid, Seq: v.IssuedAt, Keys: append([]EncKey(nil), keys...), IssuedAt: v.IssuedAt, Mbox: mbox}
		if f != nil {
			f(&s)
		}
		return s
	}
	marshal := func(s EncKeySet) []byte {
		b, err := coredet.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	set := build(nil)
	setBytes := marshal(set)
	ek2Same(t, "set", setBytes, v.Set)
	signed, err := SignEncKeySet(&set, signer)
	if err != nil {
		t.Fatal(err)
	}
	ek2Same(t, "sig", signed.Sig, v.Sig)
	signedBytes, err := signed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ek2Same(t, "signed", signedBytes, v.Signed)
	if !ed25519.Verify(idPub, setBytes, signed.Sig) {
		t.Fatal("the signature does not verify under the identity key")
	}
	back, err := UnmarshalSignedEncKeySet(signedBytes)
	if err != nil || !bytes.Equal(back.Set, setBytes) || back.KeyStateSeq != 0 || !bytes.Equal(back.Sig, signed.Sig) {
		t.Fatalf("signed set does not decode to its parts: %+v %v", back, err)
	}
	decoded, err := decodeEncKeySet(setBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*decoded, set) {
		t.Fatalf("decoded set\n got  %+v\n want %+v", *decoded, set)
	}

	// A real identity for the end-to-end checks.
	owner, err := identitytest.Hub()
	if err != nil {
		t.Fatal(err)
	}
	endToEnd := func(t *testing.T, b []byte, now uint64) error {
		_, err := VerifyEncKeySet(ek2Resign(t, b, owner), owner.AID(), owner.KEL(), now)
		return err
	}

	// VerifyEncKeySet on the day, on day 14, on day 15 and at the clock-skew edges.
	wantVerify := []string{"before_first_minus_skew", "first_within_skew", "on_the_day", "day_14",
		"last_within_skew", "last_ends_at_skew", "day_15"}
	if len(v.Verify) != len(wantVerify) {
		t.Fatalf("%d verify rows, want %d", len(v.Verify), len(wantVerify))
	}
	for i, row := range v.Verify {
		t.Run("verify/"+row.Name, func(t *testing.T) {
			if row.Name != wantVerify[i] {
				t.Fatalf("row %d is %s, want %s", i, row.Name, wantVerify[i])
			}
			got, err := ek2Content(setBytes, row.Now)
			e2e := endToEnd(t, setBytes, row.Now)
			switch row.Result {
			case "ok":
				if err != nil || e2e != nil {
					t.Fatalf("want accepted: content %v, end to end %v", err, e2e)
				}
				k, err := SelectKey(got, row.Now)
				if err != nil || row.Select == nil || !bytes.Equal(k.KID, keys[*row.Select].KID) {
					t.Fatalf("SelectKey picked %v (%v), want key %v", k, err, row.Select)
				}
			case ReasonBadKeySet:
				wantReason(t, err, ReasonBadKeySet)
				wantReason(t, e2e, ReasonBadKeySet)
				if !strings.Contains(err.Error(), "no key valid") {
					t.Fatalf("refused for another rule: %v", err)
				}
			default:
				t.Fatalf("result %q", row.Result)
			}
		})
	}

	// The two sets at a limit, accepted.
	accepted := map[string]EncKeySet{
		"keys_32": build(func(s *EncKeySet) { s.Keys = append(s.Keys, extra[:17]...) }),
		"validity_two_days": build(func(s *EncKeySet) {
			s.Keys[14].NotAfter = s.Keys[14].NotBefore + 2*EpochMS
		}),
	}
	checkEntries(t, "accepted", v.Accepted, accepted, nil, func(t *testing.T, e ek2Entry, b []byte) {
		if _, err := ek2Content(b, v.IssuedAt); err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		if err := endToEnd(t, b, v.IssuedAt); err != nil {
			t.Fatalf("%s end to end: %v", e.Name, err)
		}
	}, signer, marshal)

	// One set per refusal class, each refused for its own rule. The detail is this package's
	// wording of the rule the file names.
	null := enc(t, nil)
	badKID := keys[3]
	badKID.KID = append([]byte(nil), keys[3].KID...)
	badKID.KID[KIDLen-1] ^= 1
	structural := map[string]EncKeySet{
		"type_v1":             build(func(s *EncKeySet) { s.Type = "anet.enckeys/1" }),
		"no_keys":             build(func(s *EncKeySet) { s.Keys = []EncKey{} }),
		"keys_33":             build(func(s *EncKeySet) { s.Keys = append(s.Keys, extra...) }),
		"validity_three_days": build(func(s *EncKeySet) { s.Keys[14].NotAfter = s.Keys[14].NotBefore + 3*EpochMS }),
		"kid_repeated":        build(func(s *EncKeySet) { s.Keys = append([]EncKey{keys[0]}, keys...) }),
		"kid_mismatch":        build(func(s *EncKeySet) { s.Keys[3] = badKID }),
		"not_ascending":       build(func(s *EncKeySet) { s.Keys[2], s.Keys[3] = s.Keys[3], s.Keys[2] }),
		"mbox_epoch_0":        build(func(s *EncKeySet) { s.Mbox.Epoch = 0 }),
		"mbox_pub_31_bytes":   build(func(s *EncKeySet) { s.Mbox.Pub = s.Mbox.Pub[:31] }),
	}
	rawNeg := map[string][]byte{
		"unregistered_key_6":         rawEdit(t, setBytes, func(m fieldMap) { m[6] = null }),
		"key_64":                     rawEdit(t, setBytes, func(m fieldMap) { m[64] = null }),
		"unregistered_key_in_enckey": rawEditKey(t, setBytes, 0, func(m fieldMap) { m[6] = null }),
		"unregistered_key_in_mbox": rawEdit(t, setBytes, func(m fieldMap) {
			m[5] = rawEdit(t, m[5], func(mb fieldMap) { mb[3] = null })
		}),
		"mbox_missing": rawEdit(t, setBytes, func(m fieldMap) { delete(m, 5) }),
	}
	detail := map[string]struct {
		rule int
		text string
	}{
		"type_v1":                    {1, "type"},
		"unregistered_key_6":         {1, "key 6 is not a key of"},
		"key_64":                     {1, "key 64 is not a key of"},
		"unregistered_key_in_enckey": {1, "unknown field"},
		"unregistered_key_in_mbox":   {1, "unknown field"},
		"no_keys":                    {2, "0 keys, want 1..32"},
		"keys_33":                    {2, "33 keys, want 1..32"},
		"validity_three_days":        {2, "exceeds 2 days"},
		"kid_repeated":               {3, "repeats a kid"},
		"kid_mismatch":               {3, "kid does not match"},
		"not_ascending":              {3, "ascending not_before"},
		"mbox_missing":               {4, "key 5 (mbox) is missing"},
		"mbox_epoch_0":               {4, "mbox epoch is 0"},
		"mbox_pub_31_bytes":          {4, "mbox pub is 31 bytes"},
	}
	checkEntries(t, "negative", v.Negatives, structural, rawNeg, func(t *testing.T, e ek2Entry, b []byte) {
		d, ok := detail[e.Name]
		if !ok || d.rule != e.Rule {
			t.Fatalf("%s: rule %d, this test expects %v", e.Name, e.Rule, d)
		}
		if e.Reason == nil || *e.Reason != ReasonBadKeySet {
			t.Fatalf("%s: reason %v", e.Name, e.Reason)
		}
		_, err := ek2Content(b, v.IssuedAt)
		wantReason(t, err, ReasonBadKeySet)
		if !strings.Contains(err.Error(), d.text) {
			t.Fatalf("%s: refused for another rule: %v (want %q)", e.Name, err, d.text)
		}
		wantReason(t, endToEnd(t, b, v.IssuedAt), ReasonBadKeySet)
		if s, ok := structural[e.Name]; ok {
			_, err := SignEncKeySet(&s, signer)
			wantReason(t, err, ReasonBadKeySet)
		}
	}, signer, marshal)
	if len(v.Negatives) != len(detail) {
		t.Fatalf("%d negatives in the file, %d known here", len(v.Negatives), len(detail))
	}

	// One changed byte: the set still decodes and passes every content rule; only the signature
	// catches it.
	flipped := append([]byte(nil), setBytes...)
	flipped[len(flipped)-1] ^= 1
	ek2Same(t, "flipped set", flipped, v.Flipped.Set)
	if v.Flipped.Reason != ReasonBadSig {
		t.Fatalf("flipped reason %q", v.Flipped.Reason)
	}
	if _, err := ek2Content(flipped, v.IssuedAt); err != nil {
		t.Fatalf("flipped set refused for its content: %v", err)
	}
	if ed25519.Verify(idPub, flipped, signed.Sig) {
		t.Fatal("the signature verifies over a changed set")
	}
	s := ek2Resign(t, setBytes, owner)
	s.Set = append([]byte(nil), s.Set...)
	s.Set[len(s.Set)-1] ^= 1
	_, err = VerifyEncKeySet(s, owner.AID(), owner.KEL(), v.IssuedAt)
	wantReason(t, err, ReasonBadSig)
}

// checkEntries rebuilds every entry of the file (from a struct or from raw bytes), compares the
// bytes and the signature, and runs check on each; a name the test does not build fails.
func checkEntries(t *testing.T, kind string, entries []ek2Entry, structs map[string]EncKeySet, raws map[string][]byte,
	check func(*testing.T, ek2Entry, []byte), sign SignFunc, marshal func(EncKeySet) []byte) {
	t.Helper()
	var names []string
	for _, e := range entries {
		names = append(names, e.Name)
		var b []byte
		if s, ok := structs[e.Name]; ok {
			b = marshal(s)
		} else if r, ok := raws[e.Name]; ok {
			b = r
		} else {
			t.Fatalf("%s %s: this test does not build it", kind, e.Name)
		}
		ek2Same(t, kind+" "+e.Name+" set", b, e.Set)
		sig, _ := sign(b)
		ek2Same(t, kind+" "+e.Name+" sig", sig, e.Sig)
		t.Run(kind+"/"+e.Name, func(t *testing.T) { check(t, e, b) })
	}
	sort.Strings(names)
	if len(names) != len(structs)+len(raws) {
		t.Fatalf("%s entries in the file %v; this test builds %d", kind, names, len(structs)+len(raws))
	}
}
