// Package regpow is the proof of work a hub asks of a new AID that registers through open
// registration or an enrolment window (/register answers pow_required with a challenge). The work
// is the same on every hub: Bits leading zero bits of
//
//	pow_hash = SHA-256("anet-regpow/v1" || 0x00 || hub_aid || 0x00 || aid || 0x00 || seed(32) || nonce)
//
// (wire registry label L23), with a nonce of 1 to 32 bytes. The seed changes every hour:
//
//	seed = HMAC-SHA256(pow_key, "anet-regpow-seed/v1" || u64be(hour))
//
// (label L24), where pow_key lives only in the hub process and hour = floor(unix ms / 3 600 000).
// A hub accepts the seed of the current and of the previous hour.
//
// Check costs one hash, so a hub runs it before any expensive step. Solve is what a daemon runs:
// about 2^22 hashes, spread over all CPUs.
package regpow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"runtime"
	"strings"
	"sync"
)

const (
	// Bits is the work every hub asks for: 22 leading zero bits (core L23).
	Bits = 22
	// MaxNonce is the longest nonce a hub accepts.
	MaxNonce = 32
	// HourMillis is the length of a seed's hour.
	HourMillis = 3_600_000
)

const (
	hashLabel = "anet-regpow/v1"      // L23
	seedLabel = "anet-regpow-seed/v1" // L24
)

var (
	// ErrNUL: an AID holds U+0000, which would move the boundary between the 0x00-separated
	// fields of the hash input (CORE-E9).
	ErrNUL = errors.New("regpow: an AID holds U+0000")
	// ErrNonce: the nonce is empty or longer than MaxNonce bytes.
	ErrNonce = errors.New("regpow: the nonce is not 1 to 32 bytes")
)

// Hour is the seed hour of unix time ms.
func Hour(ms uint64) uint64 { return ms / HourMillis }

// NotAfter is the unix time (ms) at which a seed of the given hour stops being accepted: the end
// of the next hour.
func NotAfter(hour uint64) uint64 { return (hour + 2) * HourMillis }

// Seed is the L24 seed of the given hour under the hub's pow_key (32 random bytes made at start).
func Seed(key []byte, hour uint64) [32]byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(seedLabel))
	var h [8]byte
	binary.BigEndian.PutUint64(h[:], hour)
	m.Write(h[:])
	var out [32]byte
	m.Sum(out[:0])
	return out
}

// prefix is the hash input before the nonce.
func prefix(hubAID, aid string, seed [32]byte) ([]byte, error) {
	if strings.IndexByte(hubAID, 0) >= 0 || strings.IndexByte(aid, 0) >= 0 {
		return nil, ErrNUL
	}
	b := make([]byte, 0, len(hashLabel)+3+len(hubAID)+len(aid)+32+MaxNonce)
	b = append(b, hashLabel...)
	b = append(b, 0)
	b = append(b, hubAID...)
	b = append(b, 0)
	b = append(b, aid...)
	b = append(b, 0)
	b = append(b, seed[:]...)
	return b, nil
}

// Hash is the L23 hash. It refuses an AID holding U+0000 (ErrNUL) and a nonce that is empty or
// longer than 32 bytes (ErrNonce).
func Hash(hubAID, aid string, seed [32]byte, nonce []byte) ([32]byte, error) {
	if len(nonce) < 1 || len(nonce) > MaxNonce {
		return [32]byte{}, ErrNonce
	}
	b, err := prefix(hubAID, aid, seed)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append(b, nonce...)), nil
}

// zeroBits counts the leading zero bits of h.
func zeroBits(h [32]byte) int {
	n := 0
	for i := 0; i < 32; i += 8 {
		w := binary.BigEndian.Uint64(h[i:])
		if w != 0 {
			return n + bits.LeadingZeros64(w)
		}
		n += 64
	}
	return n
}

// Check reports whether nonce is a proof of work of at least want bits for aid registering at
// hubAID with seed. It is false for want < 1 or > 256 and for anything Hash refuses. Check does
// not know which seeds are current: the hub compares seed with its own first.
func Check(hubAID, aid string, seed [32]byte, nonce []byte, want int) bool {
	if want < 1 || want > 256 {
		return false
	}
	h, err := Hash(hubAID, aid, seed, nonce)
	return err == nil && zeroBits(h) >= want
}

// Solve finds a nonce (8 bytes) that passes Check for want bits. It runs one search per CPU
// (runtime.GOMAXPROCS) and returns ctx's error when ctx ends first. want must be from 1 to Bits:
// every hub asks for exactly Bits, and a challenge asking for more is refused rather than left to
// burn the CPU until the caller's deadline.
func Solve(ctx context.Context, hubAID, aid string, seed [32]byte, want int) ([]byte, error) {
	if want < 1 || want > Bits {
		return nil, fmt.Errorf("regpow: a challenge for %d bits; every hub asks for %d", want, Bits)
	}
	pre, err := prefix(hubAID, aid, seed)
	if err != nil {
		return nil, err
	}
	nonce, err := search(ctx, pre, want, runtime.GOMAXPROCS(0))
	if err != nil {
		return nil, err
	}
	if !Check(hubAID, aid, seed, nonce, want) { // the midstate shortcut must agree with Hash
		return nil, errors.New("regpow: internal error: the nonce found does not pass Check")
	}
	return nonce, nil
}

// checkEvery is how many hashes a search worker does between looks at ctx.
const checkEvery = 1 << 12

// search tries the nonces u64be(c) for c = 0, 1, 2, … split over workers (worker w takes
// c ≡ w mod workers) and returns the first one found with want leading zero bits. With one worker
// it returns the smallest such c, which the REGPOW-1 golden vector records.
func search(ctx context.Context, pre []byte, want, workers int) ([]byte, error) {
	if workers < 1 {
		workers = 1
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	found := make(chan uint64, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(c uint64) {
			defer wg.Done()
			h := newHasher(pre)
			var nonce [8]byte
			for i := 0; ; i++ {
				if i%checkEvery == 0 && ctx.Err() != nil {
					return
				}
				binary.BigEndian.PutUint64(nonce[:], c)
				if zeroBits(h.sum(nonce[:])) >= want {
					found <- c
					cancel()
					return
				}
				c += uint64(workers)
			}
		}(uint64(w))
	}
	go func() {
		wg.Wait()
		close(found)
	}()
	c, ok := <-found
	if !ok {
		if err := parent.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("regpow: the search stopped without a result")
	}
	nonce := make([]byte, 8)
	binary.BigEndian.PutUint64(nonce, c)
	return nonce, nil
}

// hasher hashes prefix || nonce for many nonces. When the SHA-256 state after the prefix can be
// saved (the standard library's can), each nonce restores it and hashes only the last block or
// two instead of the whole input.
type hasher struct {
	d     hash.Hash
	u     encoding.BinaryUnmarshaler
	state []byte
	pre   []byte
	out   [32]byte
}

func newHasher(pre []byte) *hasher {
	h := &hasher{pre: pre}
	d := sha256.New()
	d.Write(pre)
	m, ok1 := d.(encoding.BinaryMarshaler)
	u, ok2 := d.(encoding.BinaryUnmarshaler)
	if ok1 && ok2 {
		if st, err := m.MarshalBinary(); err == nil {
			h.d, h.u, h.state = d, u, st
		}
	}
	return h
}

func (h *hasher) sum(nonce []byte) [32]byte {
	if h.state != nil && h.u.UnmarshalBinary(h.state) == nil {
		h.d.Write(nonce)
		h.d.Sum(h.out[:0])
		return h.out
	}
	d := sha256.New()
	d.Write(h.pre)
	d.Write(nonce)
	d.Sum(h.out[:0])
	return h.out
}
