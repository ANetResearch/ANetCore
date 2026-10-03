package identity

// Spot checks of the fx-e fix (Replay refuses icp/rot keys that are not 32
// bytes instead of panicking in ed25519.Verify) after the round-5b merge
// (ANet an internal note): every length around 32, the key in each place a
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

// badKELs are KELs whose icp, rot or dip key is not 32 bytes, for each length.
func badKELs(t *testing.T) map[string][]SignedEvent {
	t.Helper()
	out := map[string][]SignedEvent{}
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		key := make([]byte, n)
		_, k0, _ := ed25519.GenerateKey(nil)
		icp := signedEvent(t, KeyEvent{KELType: KELType, Type: Inception, Keys: [][]byte{key},
			NextDigest: nextDigest(key), Threshold: 1, Timestamp: 1, Toad: ToadField(ToadHub)}, k0)
		out[fmt.Sprintf("icp key of %d bytes", n)] = []SignedEvent{icp}

		// A well-formed icp that commits to a key of n bytes, and the rot and the dip that reveal
		// it (signed by k0, as nothing else can sign).
		good := signedEvent(t, KeyEvent{KELType: KELType, Type: Inception, Keys: [][]byte{k0.Public().(ed25519.PublicKey)},
			NextDigest: nextDigest(key), Threshold: 1, Timestamp: 1, Toad: ToadField(ToadHub)}, k0)
		aid := good.EventID
		rot := signedEvent(t, KeyEvent{KELType: KELType, AID: aid, Seq: 1, Prev: aid, Type: Rotation, Keys: [][]byte{key},
			NextDigest: nextDigest(key), Threshold: 1, Timestamp: 2, Toad: ToadField(ToadHub)}, k0)
		out[fmt.Sprintf("rot to a key of %d bytes", n)] = []SignedEvent{good, rot}
		dip := signedEvent(t, KeyEvent{KELType: KELType, AID: aid, Seq: 1, Prev: aid, Type: Deactivation, Keys: [][]byte{key},
			Threshold: 1, Timestamp: 2}, k0)
		out[fmt.Sprintf("dip revealing a key of %d bytes", n)] = []SignedEvent{good, dip}

		// A rot with two keys whose first is fine: still not the one key KEL v2 takes.
		_, k1, _ := ed25519.GenerateKey(nil)
		pub1 := k1.Public().(ed25519.PublicKey)
		good2 := signedEvent(t, KeyEvent{KELType: KELType, Type: Inception, Keys: [][]byte{k0.Public().(ed25519.PublicKey)},
			NextDigest: nextDigest(pub1), Threshold: 1, Timestamp: 1, Toad: ToadField(ToadHub)}, k0)
		aid2 := good2.EventID
		rot2 := signedEvent(t, KeyEvent{KELType: KELType, AID: aid2, Seq: 1, Prev: aid2, Type: Rotation, Keys: [][]byte{pub1, key},
			NextDigest: nextDigest(pub1), Threshold: 1, Timestamp: 2, Toad: ToadField(ToadHub)}, k1)
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
