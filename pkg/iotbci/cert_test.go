package iotbci

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

func TestCert_IssueParseVerify(t *testing.T) {
	t.Parallel()

	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now()
	c, err := IssueCert(issuerPriv, "device-1", subPub, now.Add(-time.Hour), now.Add(time.Hour), 7)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCert(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subject != "device-1" || parsed.Serial != 7 {
		t.Fatalf("unexpected parsed cert: %#v", parsed)
	}
	if err := parsed.Verify(issuerPub, now, nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := parsed.Verify(subPub, now, nil); err == nil {
		t.Fatalf("expected verify failure with wrong issuer")
	}
}

func TestCert_VerifyExpiredAndRevoked(t *testing.T) {
	t.Parallel()

	issuerPub, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now()
	c, err := IssueCert(issuerPriv, "device-1", subPub, now.Add(-2*time.Hour), now.Add(-time.Hour), 9)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(issuerPub, now, nil); err == nil {
		t.Fatalf("expected expired error")
	}

	c2, err := IssueCert(issuerPriv, "device-2", subPub, now.Add(-time.Hour), now.Add(time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	rev := &RevocationList{
		Serials:  map[uint64]struct{}{10: {}},
		Subjects: map[string]struct{}{},
	}
	if err := c2.Verify(issuerPub, now, rev); err == nil {
		t.Fatalf("expected revoked error")
	}
	rev2 := &RevocationList{
		Subjects: map[string]struct{}{"device-2": {}},
	}
	if err := c2.Verify(issuerPub, now, rev2); err == nil {
		t.Fatalf("expected revoked error")
	}
}

func TestCert_FingerprintAndDeriveSeed(t *testing.T) {
	t.Parallel()

	_, issuerPriv, _ := ed25519.GenerateKey(rand.Reader)
	subPub, _, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now()
	c, err := IssueCert(issuerPriv, "device-1", subPub, now.Add(-time.Hour), now.Add(time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	fp := c.Fingerprint()
	if fp == ([32]byte{}) {
		t.Fatalf("expected non-zero fingerprint")
	}

	var masterSeed [32]byte
	if _, err := rand.Read(masterSeed[:]); err != nil {
		t.Fatal(err)
	}
	s1, err := DeriveEd25519Seed(masterSeed, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := DeriveEd25519Seed(masterSeed, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if s1 != s2 {
		t.Fatalf("expected deterministic seed")
	}
	s3, err := DeriveEd25519Seed(masterSeed, "device-2")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s1[:]) == hex.EncodeToString(s3[:]) {
		t.Fatalf("expected different seeds")
	}
	if _, err := DeriveEd25519Seed(masterSeed, ""); err == nil {
		t.Fatalf("expected error")
	}
}
