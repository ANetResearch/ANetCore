package regpow

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
)

// REGPOW-1 (core §5.2): golden/py/gen_v016.py writes testdata/vec-regpow-1.json from its own
// implementation; every value here is recomputed with this package and must agree byte for byte.

type vecRegpow1 struct {
	ID     string            `json:"id"`
	Labels map[string]string `json:"labels"`
	Bits   int               `json:"bits"`
	Seed   struct {
		PowKey   string `json:"pow_key"`
		MS       uint64 `json:"ms"`
		Hour     uint64 `json:"hour"`
		Message  string `json:"message"`
		Seed     string `json:"seed"`
		NotAfter uint64 `json:"not_after"`
	} `json:"seed"`
	HubAID    string `json:"hub_aid"`
	AID       string `json:"aid"`
	Prefix    string `json:"prefix"`
	Solutions []struct {
		Name     string          `json:"name"`
		Note     string          `json:"note"`
		Counter  uint64          `json:"counter"`
		Nonce    string          `json:"nonce"`
		Preimage string          `json:"preimage"`
		Hash     string          `json:"hash"`
		ZeroBits int             `json:"zero_bits"`
		Check    map[string]bool `json:"check"`
	} `json:"solutions"`
	Negatives []struct {
		Name   string `json:"name"`
		Note   string `json:"note"`
		HubAID string `json:"hub_aid"`
		AID    string `json:"aid"`
		Seed   string `json:"seed"`
		Nonce  string `json:"nonce"`
		Hash   string `json:"hash"`
		Error  string `json:"error"`
	} `json:"negatives"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%q: %v", s, err)
	}
	return b
}

func unhex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := unhex(t, s)
	if len(b) != 32 {
		t.Fatalf("%q is %d bytes", s, len(b))
	}
	return [32]byte(b)
}

func TestREGPOW1(t *testing.T) {
	raw, err := os.ReadFile("testdata/vec-regpow-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vecRegpow1
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.ID != "REGPOW-1" || v.Bits != Bits || v.Labels["hash"] != hashLabel || v.Labels["seed"] != seedLabel {
		t.Fatalf("header: %s %d %v", v.ID, v.Bits, v.Labels)
	}

	seed := unhex32(t, v.Seed.Seed)
	t.Run("seed", func(t *testing.T) {
		if Hour(v.Seed.MS) != v.Seed.Hour {
			t.Errorf("Hour(%d) = %d, want %d", v.Seed.MS, Hour(v.Seed.MS), v.Seed.Hour)
		}
		if NotAfter(v.Seed.Hour) != v.Seed.NotAfter {
			t.Errorf("NotAfter = %d, want %d", NotAfter(v.Seed.Hour), v.Seed.NotAfter)
		}
		msg := binary.BigEndian.AppendUint64([]byte(seedLabel), v.Seed.Hour)
		if hex.EncodeToString(msg) != v.Seed.Message {
			t.Errorf("message %x, want %s", msg, v.Seed.Message)
		}
		if got := Seed(unhex(t, v.Seed.PowKey), v.Seed.Hour); got != seed {
			t.Errorf("seed %x, want %x", got, seed)
		}
	})

	t.Run("prefix", func(t *testing.T) {
		pre, err := prefix(v.HubAID, v.AID, seed)
		if err != nil || hex.EncodeToString(pre) != v.Prefix {
			t.Errorf("prefix %x %v, want %s", pre, err, v.Prefix)
		}
	})

	for _, s := range v.Solutions {
		t.Run(s.Name, func(t *testing.T) {
			nonce := unhex(t, s.Nonce)
			if binary.BigEndian.Uint64(nonce) != s.Counter {
				t.Fatalf("nonce %x is not u64be(%d)", nonce, s.Counter)
			}
			pre, _ := prefix(v.HubAID, v.AID, seed)
			if got := hex.EncodeToString(append(pre, nonce...)); got != s.Preimage {
				t.Errorf("preimage\n got  %s\n want %s", got, s.Preimage)
			}
			h, err := Hash(v.HubAID, v.AID, seed, nonce)
			if err != nil || hex.EncodeToString(h[:]) != s.Hash {
				t.Errorf("hash %x %v, want %s", h, err, s.Hash)
			}
			if zeroBits(h) != s.ZeroBits {
				t.Errorf("%d zero bits, want %d", zeroBits(h), s.ZeroBits)
			}
			if len(s.Check) != 4 {
				t.Fatalf("check table %v", s.Check)
			}
			for b, want := range s.Check {
				n, err := strconv.Atoi(b)
				if err != nil {
					t.Fatal(err)
				}
				if got := Check(v.HubAID, v.AID, seed, nonce, n); got != want {
					t.Errorf("Check(%d bits) = %v, want %v", n, got, want)
				}
			}
		})
	}

	// One search worker counting from 0 returns the smallest counter: the generator's fast_8
	// (22 bits would take seconds; pass_22 is checked by Check above).
	t.Run("search", func(t *testing.T) {
		pre, _ := prefix(v.HubAID, v.AID, seed)
		for _, s := range v.Solutions {
			if s.Name != "fast_8" {
				continue
			}
			nonce, err := search(context.Background(), pre, 8, 1)
			if err != nil || binary.BigEndian.Uint64(nonce) != s.Counter {
				t.Fatalf("search(8 bits) = %x %v, want counter %d", nonce, err, s.Counter)
			}
			return
		}
		t.Fatal("no fast_8 solution in the vector")
	})

	if len(v.Negatives) < 7 {
		t.Fatalf("%d negatives", len(v.Negatives))
	}
	for _, n := range v.Negatives {
		t.Run("refuse "+n.Name, func(t *testing.T) {
			s := unhex32(t, n.Seed)
			nonce := unhex(t, n.Nonce)
			h, err := Hash(n.HubAID, n.AID, s, nonce)
			switch n.Error {
			case "":
				if err != nil || hex.EncodeToString(h[:]) != n.Hash {
					t.Errorf("hash %x %v, want %s", h, err, n.Hash)
				}
			case "nonce":
				if !errors.Is(err, ErrNonce) {
					t.Errorf("Hash = %v, want ErrNonce", err)
				}
			case "nul":
				if !errors.Is(err, ErrNUL) {
					t.Errorf("Hash = %v, want ErrNUL", err)
				}
				if _, err := Solve(context.Background(), n.HubAID, n.AID, s, 1); !errors.Is(err, ErrNUL) {
					t.Errorf("Solve = %v, want ErrNUL", err)
				}
			default:
				t.Fatalf("unknown error class %q", n.Error)
			}
			if Check(n.HubAID, n.AID, s, nonce, Bits) {
				t.Errorf("%s: Check passes", n.Note)
			}
		})
	}
}
