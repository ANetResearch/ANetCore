package identity

// Spot checks of the fx-e fix (Replay refuses icp/rot keys that are not 32
// bytes instead of panicking in ed25519.Verify) after the round-5b merge
// (ANet docs/notes/0030): every length around 32, the key in each place a
// KEL carries one, and replays racing through the process-wide cache.

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"testing"
)

// noPanic runs f and fails the test if it panics.
func noPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("%s panicked: %v", what, p)
		}
	}()
	f()
}

// badKELs are KELs whose icp or rot key is not 32 bytes, for each length.
func badKELs(t *testing.T) map[string][]SignedEvent {
	t.Helper()
	out := map[string][]SignedEvent{}
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		key := make([]byte, n)
		_, k0, _ := ed25519.GenerateKey(nil)
		icp := signedEvent(t, KeyEvent{Type: Inception, Keys: [][]byte{key}, Threshold: 1}, k0)
		out[fmt.Sprintf("icp key of %d bytes", n)] = []SignedEvent{icp}

		good := signedEvent(t, KeyEvent{Type: Inception, Keys: [][]byte{k0.Public().(ed25519.PublicKey)},
			NextDigest: nextDigest(key), Threshold: 1}, k0)
		aid := good.EventID
		rot := signedEvent(t, KeyEvent{AID: aid, Seq: 1, Prev: aid, Type: Rotation, Keys: [][]byte{key},
			NextDigest: nextDigest(key), Threshold: 1, Timestamp: 1}, k0)
		out[fmt.Sprintf("rot to a key of %d bytes", n)] = []SignedEvent{good, rot}

		// A rot with two keys whose first is fine: still not the one key
		// the baseline takes.
		_, k1, _ := ed25519.GenerateKey(nil)
		pub1 := k1.Public().(ed25519.PublicKey)
		good2 := signedEvent(t, KeyEvent{Type: Inception, Keys: [][]byte{k0.Public().(ed25519.PublicKey)},
			NextDigest: nextDigest(pub1), Threshold: 1}, k0)
		aid2 := good2.EventID
		rot2 := signedEvent(t, KeyEvent{AID: aid2, Seq: 1, Prev: aid2, Type: Rotation, Keys: [][]byte{pub1, key},
			NextDigest: nextDigest(pub1), Threshold: 1, Timestamp: 1}, k0)
		out[fmt.Sprintf("rot to two keys, the second of %d bytes", n)] = []SignedEvent{good2, rot2}
	}
	return out
}

func TestSpotEveryWrongKeyLengthIsRefusedNotAPanic(t *testing.T) {
	for name, kel := range badKELs(t) {
		noPanic(t, name, func() {
			if _, err := Replay(kel); err == nil {
				t.Errorf("%s: replayed", name)
			}
			for seq := uint64(0); seq < uint64(len(kel)); seq++ {
				if err := VerifyObject(kel, kel[0].EventID, seq, 2, []byte("x"), make([]byte, 64)); err == nil {
					t.Errorf("%s: an object verified at seq %d", name, seq)
				}
			}
		})
	}
}

// A drt event may carry a delegated key of any length (it signs nothing
// the KEL verifies), and the KEL replays; the events after it are still
// checked against the owner's 32-byte key, and nothing panics.
func TestSpotAShortDelegatedKeyDoesNotReachAVerification(t *testing.T) {
	_, k0, _ := ed25519.GenerateKey(nil)
	_, k1, _ := ed25519.GenerateKey(nil)
	icp := signedEvent(t, KeyEvent{Type: Inception, Keys: [][]byte{k0.Public().(ed25519.PublicKey)},
		NextDigest: nextDigest(k1.Public().(ed25519.PublicKey)), Threshold: 1}, k0)
	aid := icp.EventID
	drt := signedEvent(t, KeyEvent{AID: aid, Seq: 1, Prev: aid, Type: Delegation,
		Keys: [][]byte{make([]byte, 31)}, Threshold: 1, Timestamp: 1}, k0)
	ixn := signedEvent(t, KeyEvent{AID: aid, Seq: 2, Prev: drt.EventID, Type: Interaction,
		Keys: [][]byte{}, Threshold: 1, Timestamp: 2}, k0)
	kel := []SignedEvent{icp, drt, ixn}
	noPanic(t, "a KEL with a short delegated key", func() {
		states, err := Replay(kel)
		if err != nil {
			t.Fatalf("replay: %v", err)
		}
		if n := len(states[2].DelegatedKeys); n != 1 {
			t.Fatalf("delegated keys = %d", n)
		}
		pre := []byte("object")
		if err := VerifyObject(kel, aid, 2, 3, pre, ed25519.Sign(k0, pre)); err != nil {
			t.Fatalf("an object signed by the owner's key: %v", err)
		}
		if err := VerifyObject(kel, aid, 2, 3, pre, make([]byte, 64)); err == nil {
			t.Fatal("a zero signature verified")
		}
	})
}

// The same KELs replayed from many goroutines at once through the
// process-wide cache (the hub installs one): each answer is the refusal,
// from the cache or not, and none panics.
func TestSpotRacingReplaysThroughTheCacheRefuseEveryWrongLength(t *testing.T) {
	prev := SetReplayCache(NewReplayCache(1 << 20))
	t.Cleanup(func() { SetReplayCache(prev) })
	kels := badKELs(t)
	var wg sync.WaitGroup
	errs := make(chan string, 1024)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if p := recover(); p != nil {
					errs <- fmt.Sprintf("panic: %v", p)
				}
			}()
			for round := 0; round < 3; round++ {
				for name, kel := range kels {
					if _, err := Replay(kel); err == nil {
						errs <- name + ": replayed"
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}
