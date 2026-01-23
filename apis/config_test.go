package apis

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func TestParseEd25519PublicKeyHex(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := hex.EncodeToString(pub)
	got, err := ParseEd25519PublicKeyHex(s)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pub) {
		t.Fatalf("mismatch")
	}
	if _, err := ParseEd25519PublicKeyHex("zz"); err == nil {
		t.Fatalf("expected error")
	}
	if _, err := ParseEd25519PublicKeyHex(hex.EncodeToString(pub[:10])); err == nil {
		t.Fatalf("expected length error")
	}
}

func TestParseEd25519PrivateKeyHex(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seed := priv.Seed()

	gotSeed, err := ParseEd25519PrivateKeyHex(hex.EncodeToString(seed))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotSeed.Seed()) != string(seed) {
		t.Fatalf("seed mismatch")
	}

	gotPriv, err := ParseEd25519PrivateKeyHex(hex.EncodeToString(priv))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPriv) != string(priv) {
		t.Fatalf("priv mismatch")
	}

	if _, err := ParseEd25519PrivateKeyHex("00"); err == nil {
		t.Fatalf("expected length error")
	}
}

func TestParseCertHexOrBase64(t *testing.T) {
	t.Parallel()

	_, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	cert, err := iotbci.IssueCert(issuerPriv, "device-1", subPub, now.Add(-time.Hour), now.Add(time.Hour), 123)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := cert.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	hexStr := hex.EncodeToString(raw)
	base64Str := base64.StdEncoding.EncodeToString(raw)

	c1, err := ParseCertHexOrBase64(hexStr)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := ParseCertHexOrBase64(base64Str)
	if err != nil {
		t.Fatal(err)
	}
	if c1.Serial != cert.Serial || c2.Serial != cert.Serial {
		t.Fatalf("serial mismatch")
	}

	if _, err := ParseCertHexOrBase64("not-hex-and-not-base64"); err == nil {
		t.Fatalf("expected error")
	}
}
