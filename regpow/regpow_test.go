package regpow

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	tHub = "bafyreihubhubhubhubhubhubhubhubhubhubhubhubhubhubhubhubhubhu"
	tAID = "bafyreiagentagentagentagentagentagentagentagentagentagentage"
)

var tSeed = Seed([]byte("test pow key, 32 bytes long....."), 490897)

func TestSolveThenCheck(t *testing.T) {
	for _, bits := range []int{1, 4, 8, 12, 16} {
		nonce, err := Solve(context.Background(), tHub, tAID, tSeed, bits)
		if err != nil {
			t.Fatalf("%d bits: %v", bits, err)
		}
		if len(nonce) != 8 {
			t.Fatalf("nonce of %d bytes", len(nonce))
		}
		if !Check(tHub, tAID, tSeed, nonce, bits) {
			t.Fatalf("%d bits: Solve's nonce fails Check", bits)
		}
		// the work is bound to the hub, the AID and the seed: each changes the hash
		h, _ := Hash(tHub, tAID, tSeed, nonce)
		for _, o := range [][3]any{{tHub + "x", tAID, tSeed}, {tHub, tAID + "x", tSeed}, {tHub, tAID, Seed(nil, 1)}} {
			if g, _ := Hash(o[0].(string), o[1].(string), o[2].([32]byte), nonce); g == h {
				t.Fatalf("%d bits: the same hash for another hub, AID or seed", bits)
			}
		}
	}
}

// TestSolve22 runs the real work once: what a daemon does on registration.
func TestSolve22(t *testing.T) {
	start := time.Now()
	nonce, err := Solve(context.Background(), tHub, tAID, tSeed, Bits)
	if err != nil {
		t.Fatal(err)
	}
	if !Check(tHub, tAID, tSeed, nonce, Bits) {
		t.Fatal("the nonce fails Check")
	}
	t.Logf("22 bits in %v", time.Since(start))
}

// TestHasherMatchesHash: the saved-state shortcut Solve uses gives the same hash as Hash for
// prefixes of every length around the block boundaries and nonces of every allowed length.
func TestHasherMatchesHash(t *testing.T) {
	for aidLen := 0; aidLen < 140; aidLen += 7 {
		aid := strings.Repeat("a", aidLen)
		pre, err := prefix(tHub, aid, tSeed)
		if err != nil {
			t.Fatal(err)
		}
		h := newHasher(pre)
		if h.state == nil {
			t.Fatal("the SHA-256 state cannot be saved; Solve would hash the whole input every time")
		}
		for n := 1; n <= MaxNonce; n++ {
			nonce := make([]byte, n)
			for i := range nonce {
				nonce[i] = byte(aidLen*31 + n*7 + i)
			}
			want, err := Hash(tHub, aid, tSeed, nonce)
			if err != nil {
				t.Fatal(err)
			}
			if got := h.sum(nonce); got != want {
				t.Fatalf("aid %d bytes, nonce %d bytes: shortcut %x, Hash %x", aidLen, n, got, want)
			}
		}
		// the fallback path (no saved state) agrees too
		f := &hasher{pre: pre}
		if got, want := f.sum([]byte{1, 2, 3}), sha256.Sum256(append(append([]byte(nil), pre...), 1, 2, 3)); got != want {
			t.Fatal("fallback hasher differs")
		}
	}
}

func TestCheckRefuses(t *testing.T) {
	nonce, err := Solve(context.Background(), tHub, tAID, tSeed, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		hub   string
		aid   string
		nonce []byte
		bits  int
	}{
		{"0 bits", tHub, tAID, nonce, 0},
		{"negative bits", tHub, tAID, nonce, -5},
		{"257 bits", tHub, tAID, nonce, 257},
		{"empty nonce", tHub, tAID, nil, 1},
		{"33-byte nonce", tHub, tAID, make([]byte, 33), 1},
		{"NUL in hub", tHub + "\x00", tAID, nonce, 8},
		{"NUL in aid", tHub, "\x00" + tAID, nonce, 8},
	} {
		if Check(c.hub, c.aid, tSeed, c.nonce, c.bits) {
			t.Errorf("%s: Check passes", c.name)
		}
	}
	// a nonce of 32 bytes is allowed
	if _, err := Hash(tHub, tAID, tSeed, make([]byte, 32)); err != nil {
		t.Errorf("32-byte nonce: %v", err)
	}
}

// TestHashNUL: each 0x00-separated text field refuses U+0000 by itself (CORE-E9). Without the
// check ("a\0b", "c") and ("a", "b\0c") hash the same bytes.
func TestHashNUL(t *testing.T) {
	n := []byte{7}
	if _, err := Hash("a\x00b", "c", tSeed, n); !errors.Is(err, ErrNUL) {
		t.Errorf("hub_aid: %v", err)
	}
	if _, err := Hash("a", "b\x00c", tSeed, n); !errors.Is(err, ErrNUL) {
		t.Errorf("aid: %v", err)
	}
	if _, err := Hash("a", "bc", tSeed, n); err != nil {
		t.Errorf("no NUL: %v", err)
	}
}

func TestSolveRefuses(t *testing.T) {
	for _, bits := range []int{0, -1, Bits + 1, 64} {
		if _, err := Solve(context.Background(), tHub, tAID, tSeed, bits); err == nil {
			t.Errorf("%d bits: Solve accepted the challenge", bits)
		}
	}
	if _, err := Solve(context.Background(), tHub, tAID+"\x00", tSeed, 4); !errors.Is(err, ErrNUL) {
		t.Errorf("NUL: %v", err)
	}
}

// TestSolveStopsWithContext: Solve returns the context's error promptly when it ends first.
func TestSolveStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Solve(ctx, tHub, tAID, tSeed, Bits); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	// 64 bits will not be found; the deadline ends the search
	pre, _ := prefix(tHub, tAID, tSeed)
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := search(ctx, pre, 64, 4); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("search ran %v past a 50 ms deadline", d)
	}
}

func TestSeedAndHours(t *testing.T) {
	k := []byte("k")
	if Seed(k, 1) == Seed(k, 2) || Seed(k, 1) == Seed([]byte("j"), 1) {
		t.Fatal("seeds repeat across hours or keys")
	}
	if Hour(3_599_999) != 0 || Hour(3_600_000) != 1 {
		t.Fatal("hour boundaries")
	}
	// a seed made during hour h is good to the end of hour h+1
	if NotAfter(10) != 12*HourMillis {
		t.Fatalf("NotAfter(10) = %d", NotAfter(10))
	}
}

func TestZeroBits(t *testing.T) {
	var h [32]byte
	if zeroBits(h) != 256 {
		t.Fatal("all zero")
	}
	for i := 0; i < 256; i++ {
		var x [32]byte
		x[i/8] = 0x80 >> (i % 8)
		if zeroBits(x) != i {
			t.Fatalf("bit %d: %d", i, zeroBits(x))
		}
	}
}
