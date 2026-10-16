package regpow

import (
	"context"
	"encoding/binary"
	"runtime"
	"slices"
	"testing"
	"time"
)

// BenchmarkSolve22 measures one registration's work at the real difficulty (22 bits) with all
// CPUs, as a daemon runs it. Each iteration uses another seed, so the work varies as it does in
// the field; besides ns/op (the mean) it reports the median (median-ms) and the 90th percentile
// (p90-ms) of the iterations. Run with -benchtime=40x or more for a stable median.
func BenchmarkSolve22(b *testing.B) {
	benchSolve(b, runtime.GOMAXPROCS(0))
}

// BenchmarkSolve22OneCPU is the same with one search worker: the work on a single-core device.
func BenchmarkSolve22OneCPU(b *testing.B) {
	benchSolve(b, 1)
}

func benchSolve(b *testing.B, workers int) {
	key := []byte("benchmark pow key, 32 bytes long")
	var took []time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seed := Seed(key, uint64(i))
		pre, err := prefix(tHub, tAID, seed)
		if err != nil {
			b.Fatal(err)
		}
		start := time.Now()
		nonce, err := search(context.Background(), pre, Bits, workers)
		took = append(took, time.Since(start))
		if err != nil || !Check(tHub, tAID, seed, nonce, Bits) {
			b.Fatalf("iteration %d: %x %v", i, nonce, err)
		}
		_ = binary.BigEndian.Uint64(nonce)
	}
	b.StopTimer()
	slices.Sort(took)
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	b.ReportMetric(ms(took[len(took)/2]), "median-ms")
	b.ReportMetric(ms(took[len(took)*9/10]), "p90-ms")
}

// BenchmarkHash is the cost of one Check on the hub: one hash of the whole input.
func BenchmarkHash(b *testing.B) {
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for i := 0; i < b.N; i++ {
		if _, err := Hash(tHub, tAID, tSeed, nonce); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHasher is the cost of one try in Solve (restore the saved state, hash the tail).
func BenchmarkHasher(b *testing.B) {
	pre, _ := prefix(tHub, tAID, tSeed)
	h := newHasher(pre)
	var nonce [8]byte
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint64(nonce[:], uint64(i))
		h.sum(nonce[:])
	}
}
