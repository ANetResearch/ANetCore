package regpow

import (
	"strings"
	"testing"
)

// FuzzCheck: Check never panics; it passes only when Hash accepts the input and the hash has the
// leading zero bits asked for; anything with U+0000 in an AID, a nonce outside 1 to 32 bytes or a
// bit count outside 1 to 256 fails.
func FuzzCheck(f *testing.F) {
	f.Add(tHub, tAID, []byte("seed"), []byte{0, 0, 0, 0, 0, 0, 0, 1}, 1)
	f.Add("", "", []byte{}, []byte{}, 0)
	f.Add("a\x00b", "c", []byte{1}, []byte{2}, 1)
	f.Add("a", "b", []byte{1}, make([]byte, 33), 1)
	f.Add("a", "b", []byte{1}, []byte{9}, 300)
	f.Fuzz(func(t *testing.T, hub, aid string, seedIn, nonce []byte, bits int) {
		var seed [32]byte
		copy(seed[:], seedIn)
		ok := Check(hub, aid, seed, nonce, bits)
		h, err := Hash(hub, aid, seed, nonce)
		bad := strings.IndexByte(hub, 0) >= 0 || strings.IndexByte(aid, 0) >= 0 || len(nonce) < 1 || len(nonce) > MaxNonce
		if bad != (err != nil) {
			t.Fatalf("Hash error %v for an input that is bad=%v", err, bad)
		}
		want := err == nil && bits >= 1 && bits <= 256 && zeroBits(h) >= bits
		if ok != want {
			t.Fatalf("Check = %v, want %v (bits %d, zero bits %d, err %v)", ok, want, bits, zeroBits(h), err)
		}
		if err == nil {
			// the saved-state shortcut agrees with Hash
			pre, _ := prefix(hub, aid, seed)
			if newHasher(pre).sum(nonce) != h {
				t.Fatal("the shortcut hasher differs from Hash")
			}
		}
	})
}
