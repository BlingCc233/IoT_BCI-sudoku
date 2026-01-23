package iotbci

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	certVersionV1 = 1

	maxCertLen    = 4096
	maxSubjectLen = 255
)

var (
	ErrCertInvalid = errors.New("iotbci: invalid certificate")
	ErrCertExpired = errors.New("iotbci: certificate expired")
	ErrCertRevoked = errors.New("iotbci: certificate revoked")
)

// Cert is a compact, thesis-friendly identity certificate.
//
// It is intentionally minimal: a subject string + an Ed25519 public key, signed by a master key.
type Cert struct {
	Version uint8
	Serial  uint64

	NotBefore time.Time
	NotAfter  time.Time

	Subject   string
	PublicKey ed25519.PublicKey

	Signature []byte // 64 bytes (Ed25519)
}

func (c *Cert) validateBasic() error {
	if c == nil {
		return fmt.Errorf("%w: nil", ErrCertInvalid)
	}
	if c.Version != certVersionV1 {
		return fmt.Errorf("%w: unsupported version %d", ErrCertInvalid, c.Version)
	}
	if len(c.Subject) == 0 || len(c.Subject) > maxSubjectLen {
		return fmt.Errorf("%w: invalid subject length %d", ErrCertInvalid, len(c.Subject))
	}
	if len(c.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid public key length %d", ErrCertInvalid, len(c.PublicKey))
	}
	if c.NotAfter.Before(c.NotBefore) {
		return fmt.Errorf("%w: invalid validity window", ErrCertInvalid)
	}
	return nil
}

func (c *Cert) marshalBody() ([]byte, error) {
	if err := c.validateBasic(); err != nil {
		return nil, err
	}

	subject := []byte(c.Subject)
	bodyLen := 1 + 8 + 8 + 8 + 2 + len(subject) + 32
	body := make([]byte, bodyLen)
	i := 0
	body[i] = c.Version
	i++
	binary.BigEndian.PutUint64(body[i:i+8], c.Serial)
	i += 8
	binary.BigEndian.PutUint64(body[i:i+8], uint64(c.NotBefore.Unix()))
	i += 8
	binary.BigEndian.PutUint64(body[i:i+8], uint64(c.NotAfter.Unix()))
	i += 8
	binary.BigEndian.PutUint16(body[i:i+2], uint16(len(subject)))
	i += 2
	copy(body[i:i+len(subject)], subject)
	i += len(subject)
	copy(body[i:i+32], c.PublicKey)
	i += 32
	if i != len(body) {
		return nil, fmt.Errorf("%w: internal marshal length mismatch", ErrCertInvalid)
	}
	return body, nil
}

func (c *Cert) MarshalBinary() ([]byte, error) {
	body, err := c.marshalBody()
	if err != nil {
		return nil, err
	}
	if len(c.Signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: missing signature", ErrCertInvalid)
	}
	out := make([]byte, 0, len(body)+ed25519.SignatureSize)
	out = append(out, body...)
	out = append(out, c.Signature...)
	return out, nil
}

func ParseCert(b []byte) (*Cert, error) {
	if len(b) < 1+8+8+8+2+32+ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: too short", ErrCertInvalid)
	}
	if len(b) > maxCertLen {
		return nil, fmt.Errorf("%w: too large", ErrCertInvalid)
	}

	i := 0
	version := b[i]
	i++
	serial := binary.BigEndian.Uint64(b[i : i+8])
	i += 8
	notBefore := int64(binary.BigEndian.Uint64(b[i : i+8]))
	i += 8
	notAfter := int64(binary.BigEndian.Uint64(b[i : i+8]))
	i += 8
	subjectLen := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	if subjectLen <= 0 || subjectLen > maxSubjectLen {
		return nil, fmt.Errorf("%w: invalid subject length", ErrCertInvalid)
	}
	if len(b) < i+subjectLen+32+ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: truncated", ErrCertInvalid)
	}

	subject := string(b[i : i+subjectLen])
	i += subjectLen
	pub := make([]byte, 32)
	copy(pub, b[i:i+32])
	i += 32
	sig := make([]byte, ed25519.SignatureSize)
	copy(sig, b[i:i+ed25519.SignatureSize])
	i += ed25519.SignatureSize
	if i != len(b) {
		return nil, fmt.Errorf("%w: trailing bytes", ErrCertInvalid)
	}

	c := &Cert{
		Version:   version,
		Serial:    serial,
		NotBefore: time.Unix(notBefore, 0),
		NotAfter:  time.Unix(notAfter, 0),
		Subject:   subject,
		PublicKey: pub,
		Signature: sig,
	}
	if err := c.validateBasic(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cert) Verify(issuerPublic ed25519.PublicKey, now time.Time, revocation *RevocationList) error {
	if err := c.validateBasic(); err != nil {
		return err
	}
	if len(issuerPublic) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid issuer public key length", ErrCertInvalid)
	}
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return fmt.Errorf("%w: not valid at %s", ErrCertExpired, now.UTC().Format(time.RFC3339))
	}
	if revocation != nil && revocation.IsRevoked(c) {
		return ErrCertRevoked
	}

	body, err := c.marshalBody()
	if err != nil {
		return err
	}
	if !ed25519.Verify(issuerPublic, body, c.Signature) {
		return fmt.Errorf("%w: signature mismatch", ErrCertInvalid)
	}
	return nil
}

func IssueCert(issuerPrivate ed25519.PrivateKey, subject string, subjectPublic ed25519.PublicKey, notBefore time.Time, notAfter time.Time, serial uint64) (*Cert, error) {
	if len(issuerPrivate) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: invalid issuer private key length", ErrCertInvalid)
	}
	c := &Cert{
		Version:   certVersionV1,
		Serial:    serial,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Subject:   subject,
		PublicKey: append([]byte(nil), subjectPublic...),
		Signature: nil,
	}
	body, err := c.marshalBody()
	if err != nil {
		return nil, err
	}
	c.Signature = ed25519.Sign(issuerPrivate, body)
	return c, nil
}

func (c *Cert) Fingerprint() [32]byte {
	if c == nil {
		return [32]byte{}
	}
	b, err := c.MarshalBinary()
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(b)
}

// DeriveEd25519Seed deterministically derives an Ed25519 seed from a master seed and a device ID.
// This supports multi-device provisioning with a single "master secret" in manufacturing.
func DeriveEd25519Seed(masterSeed [32]byte, deviceID string) ([32]byte, error) {
	var out [32]byte
	if deviceID == "" || len(deviceID) > maxSubjectLen {
		return out, fmt.Errorf("device id length invalid: %d", len(deviceID))
	}
	r := hkdf.New(sha256.New, masterSeed[:], nil, []byte("iotbci-sudoku:ed25519-seed:"+deviceID))
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, err
	}
	return out, nil
}

type RevocationList struct {
	Serials  map[uint64]struct{}
	Subjects map[string]struct{}
}

func (r *RevocationList) IsRevoked(c *Cert) bool {
	if r == nil || c == nil {
		return false
	}
	if len(r.Serials) > 0 {
		if _, ok := r.Serials[c.Serial]; ok {
			return true
		}
	}
	if len(r.Subjects) > 0 {
		if _, ok := r.Subjects[c.Subject]; ok {
			return true
		}
	}
	return false
}
