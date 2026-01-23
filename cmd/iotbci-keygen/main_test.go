package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

func TestIoTBCIUserHash(t *testing.T) {
	t.Parallel()

	var seed [32]byte
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed[:])

	wantSum := sha256.Sum256(seed[:])
	want := wantSum[:8]

	got := iotbciUserHash(priv)
	for i := 0; i < 8; i++ {
		if got[i] != want[i] {
			t.Fatalf("mismatch at %d: got=%x want=%x", i, got[i], want[i])
		}
	}
}
