package sudoku

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"time"
)

// fastRNG is a small, fast, non-cryptographic PRNG for traffic-appearance randomness.
//
// We intentionally do NOT use it for any cryptographic purpose. It is used only for:
// - choosing a random puzzle/permutation
// - deciding whether to insert padding bytes
//
// This avoids the overhead of math/rand in hot paths.
type fastRNG struct {
	s0 uint64
	s1 uint64
}

func newFastRNG() fastRNG {
	var seedBytes [16]byte
	if _, err := crypto_rand.Read(seedBytes[:]); err != nil {
		// Last-resort fallback (still fine for non-crypto randomness).
		now := uint64(time.Now().UnixNano())
		binary.LittleEndian.PutUint64(seedBytes[0:8], now)
		binary.LittleEndian.PutUint64(seedBytes[8:16], now^0x9e3779b97f4a7c15)
	}
	seed0 := binary.LittleEndian.Uint64(seedBytes[0:8])
	seed1 := binary.LittleEndian.Uint64(seedBytes[8:16])

	// Initialize xoroshiro state via splitmix64 expansion.
	s0 := splitmix64(&seed0)
	s1 := splitmix64(&seed1)
	if s0 == 0 && s1 == 0 {
		s1 = 1
	}
	return fastRNG{s0: s0, s1: s1}
}

func splitmix64(x *uint64) uint64 {
	*x += 0x9e3779b97f4a7c15
	z := *x
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func rotl64(x uint64, k int) uint64 { return (x << k) | (x >> (64 - k)) }

// Uint64 returns the next 64 bits from xoroshiro128+.
func (r *fastRNG) Uint64() uint64 {
	s0 := r.s0
	s1 := r.s1
	res := s0 + s1

	s1 ^= s0
	r.s0 = rotl64(s0, 55) ^ s1 ^ (s1 << 14)
	r.s1 = rotl64(s1, 36)
	return res
}

func (r *fastRNG) Uint32() uint32 { return uint32(r.Uint64()) }

// Float32 returns a uniform float32 in [0,1).
func (r *fastRNG) Float32() float32 {
	// Use the top 24 bits to fill float32 mantissa-like range.
	return float32(r.Uint32()>>8) / float32(1<<24)
}

