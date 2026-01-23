package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func main() {
	var (
		genMaster = flag.Bool("gen-master", false, "generate a new Ed25519 master keypair")
		genKey    = flag.Bool("gen-key", false, "generate a new Ed25519 keypair (device/server)")

		issueCert = flag.Bool("issue-cert", false, "issue a device/server cert (requires -master-priv-hex, -subject, -pub-hex)")

		masterPrivHex = flag.String("master-priv-hex", "", "master private key hex (64 bytes)")
		subject       = flag.String("subject", "", "certificate subject (device id)")
		pubHex        = flag.String("pub-hex", "", "subject public key hex (32 bytes)")
		serial        = flag.Uint64("serial", 1, "certificate serial")
		days          = flag.Int("days", 365, "validity days")

		masterSeedHex = flag.String("master-seed-hex", "", "optional 32-byte master seed hex for deterministic device key derivation")
		deviceID      = flag.String("device-id", "", "device id for -derive-device-key")
		deriveDevice  = flag.Bool("derive-device-key", false, "derive device key from master seed + device id")
	)
	flag.Parse()

	switch {
	case *genMaster:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		fatal(err)
		fmt.Printf("master_public_key_hex=%s\n", hex.EncodeToString(pub))
		fmt.Printf("master_private_key_hex=%s\n", hex.EncodeToString(priv))
		return
	case *genKey:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		fatal(err)
		fmt.Printf("public_key_hex=%s\n", hex.EncodeToString(pub))
		fmt.Printf("private_key_hex=%s\n", hex.EncodeToString(priv))
		fmt.Printf("seed_hex=%s\n", hex.EncodeToString(priv.Seed()))
		userHash := iotbciUserHash(priv)
		fmt.Printf("user_hash_hex=%s\n", hex.EncodeToString(userHash[:]))
		return
	case *deriveDevice:
		if *masterSeedHex == "" || *deviceID == "" {
			fatal(fmt.Errorf("-master-seed-hex and -device-id are required"))
		}
		seedBytes, err := hex.DecodeString(*masterSeedHex)
		fatal(err)
		if len(seedBytes) != 32 {
			fatal(fmt.Errorf("master seed must be 32 bytes, got %d", len(seedBytes)))
		}
		var masterSeed [32]byte
		copy(masterSeed[:], seedBytes)
		seed, err := iotbci.DeriveEd25519Seed(masterSeed, *deviceID)
		fatal(err)
		priv := ed25519.NewKeyFromSeed(seed[:])
		pub := priv.Public().(ed25519.PublicKey)
		fmt.Printf("public_key_hex=%s\n", hex.EncodeToString(pub))
		fmt.Printf("private_key_hex=%s\n", hex.EncodeToString(priv))
		fmt.Printf("seed_hex=%s\n", hex.EncodeToString(priv.Seed()))
		userHash := iotbciUserHash(priv)
		fmt.Printf("user_hash_hex=%s\n", hex.EncodeToString(userHash[:]))
		return
	case *issueCert:
		if *masterPrivHex == "" || *subject == "" || *pubHex == "" {
			fatal(fmt.Errorf("-master-priv-hex, -subject, -pub-hex are required"))
		}
		mprivBytes, err := hex.DecodeString(*masterPrivHex)
		fatal(err)
		if len(mprivBytes) != ed25519.PrivateKeySize {
			fatal(fmt.Errorf("master private key must be 64 bytes, got %d", len(mprivBytes)))
		}
		pubBytes, err := hex.DecodeString(*pubHex)
		fatal(err)
		if len(pubBytes) != ed25519.PublicKeySize {
			fatal(fmt.Errorf("public key must be 32 bytes, got %d", len(pubBytes)))
		}
		now := time.Now()
		nb := now.Add(-5 * time.Minute)
		na := now.Add(time.Duration(*days) * 24 * time.Hour)
		cert, err := iotbci.IssueCert(ed25519.PrivateKey(mprivBytes), *subject, ed25519.PublicKey(pubBytes), nb, na, *serial)
		fatal(err)
		raw, err := cert.MarshalBinary()
		fatal(err)
		fmt.Printf("cert_base64=%s\n", base64.StdEncoding.EncodeToString(raw))
		fmt.Printf("cert_hex=%s\n", hex.EncodeToString(raw))
		return
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func iotbciUserHash(priv ed25519.PrivateKey) [8]byte {
	// Mirrors iotbci user hash definition: Trunc8(SHA-256(seed)).
	var out [8]byte
	if len(priv) != ed25519.PrivateKeySize {
		return out
	}
	sum := sha256.Sum256(priv.Seed())
	copy(out[:], sum[:8])
	return out
}

func fatal(err error) {
	if err == nil {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
