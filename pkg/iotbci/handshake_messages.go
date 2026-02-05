package iotbci

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	clientHelloMinSize = 2 + 8 + 16 + 8 + 32 + 2 + ed25519.SignatureSize
	serverHelloMinSize = 2 + 8 + 16 + 16 + 32 + 2 + 32 + ed25519.SignatureSize
	clientFinishSize   = 32 + 32 + 16
)

var (
	ErrHandshakeMalformed = errors.New("iotbci: malformed handshake")
)

func aeadToID(m AEADMethod) (uint16, error) {
	switch m {
	case AEADNone:
		return 0, nil
	case AEADAES128GCM:
		return 1, nil
	case AEADChaCha20Poly1305:
		return 2, nil
	default:
		return 0, fmt.Errorf("unknown aead: %s", m)
	}
}

func idToAEAD(id uint16) (AEADMethod, error) {
	switch id {
	case 0:
		return AEADNone, nil
	case 1:
		return AEADAES128GCM, nil
	case 2:
		return AEADChaCha20Poly1305, nil
	default:
		return "", fmt.Errorf("unknown aead id: %d", id)
	}
}

func encodeFlags(sessionAEAD AEADMethod, enablePureDownlink bool, enablePackedUplink bool) (uint16, error) {
	aeadID, err := aeadToID(sessionAEAD)
	if err != nil {
		return 0, err
	}
	var flags uint16
	flags |= aeadID & 0x0003
	if enablePureDownlink {
		flags |= 1 << 2
	}
	if enablePackedUplink {
		flags |= 1 << 3
	}
	return flags, nil
}

func decodeFlags(flags uint16) (AEADMethod, bool, bool, error) {
	aeadID := flags & 0x0003
	aead, err := idToAEAD(aeadID)
	if err != nil {
		return "", false, false, err
	}
	enablePureDownlink := (flags & (1 << 2)) != 0
	enablePackedUplink := (flags & (1 << 3)) != 0
	return aead, enablePureDownlink, enablePackedUplink, nil
}

// userHashFromPrivateKey preserves the legacy "private-key-hash user matching" property:
// it is stable per device and can be used for accounting without exposing the private key.
func userHashFromPrivateKey(priv ed25519.PrivateKey) [8]byte {
	var out [8]byte
	if len(priv) != ed25519.PrivateKeySize {
		return out
	}
	seed := priv.Seed()
	sum := sha256.Sum256(seed)
	copy(out[:], sum[:8])
	return out
}

type parsedClientHello struct {
	Flags      uint16
	Timestamp  uint64
	Nonce      [16]byte
	UserHash   [8]byte
	Ephemeral  [32]byte
	CertRaw    []byte
	Cert       *Cert
	Signature  []byte
	BodyNoSig  []byte
	BodyHash32 [32]byte
}

func parseClientHello(body []byte) (*parsedClientHello, error) {
	if len(body) < clientHelloMinSize {
		return nil, fmt.Errorf("%w: client hello too short", ErrHandshakeMalformed)
	}

	i := 0
	flags := binary.BigEndian.Uint16(body[i : i+2])
	i += 2
	ts := binary.BigEndian.Uint64(body[i : i+8])
	i += 8
	var nonce [16]byte
	copy(nonce[:], body[i:i+16])
	i += 16
	var userHash [8]byte
	copy(userHash[:], body[i:i+8])
	i += 8
	var eph [32]byte
	copy(eph[:], body[i:i+32])
	i += 32
	if len(body) < i+2 {
		return nil, fmt.Errorf("%w: truncated cert len", ErrHandshakeMalformed)
	}
	certLen := int(binary.BigEndian.Uint16(body[i : i+2]))
	i += 2
	if certLen <= 0 || certLen > maxCertLen {
		return nil, fmt.Errorf("%w: invalid cert len %d", ErrHandshakeMalformed, certLen)
	}
	if len(body) < i+certLen+ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: truncated cert/sig", ErrHandshakeMalformed)
	}
	certRaw := body[i : i+certLen]
	i += certLen
	sig := body[i : i+ed25519.SignatureSize]
	i += ed25519.SignatureSize
	if i != len(body) {
		return nil, fmt.Errorf("%w: trailing bytes", ErrHandshakeMalformed)
	}

	cert, err := ParseCert(certRaw)
	if err != nil {
		return nil, err
	}

	noSig := body[:len(body)-ed25519.SignatureSize]
	h := sha256.Sum256(noSig)
	return &parsedClientHello{
		Flags:      flags,
		Timestamp:  ts,
		Nonce:      nonce,
		UserHash:   userHash,
		Ephemeral:  eph,
		CertRaw:    certRaw,
		Cert:       cert,
		Signature:  sig,
		BodyNoSig:  noSig,
		BodyHash32: h,
	}, nil
}

func buildClientHello(flags uint16, timestamp uint64, nonce [16]byte, userHash [8]byte, eph [32]byte, certRaw []byte, priv ed25519.PrivateKey) ([]byte, [32]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, [32]byte{}, fmt.Errorf("%w: invalid client private key", ErrAuthFailed)
	}
	if len(certRaw) <= 0 || len(certRaw) > maxCertLen {
		return nil, [32]byte{}, fmt.Errorf("%w: invalid cert len %d", ErrHandshakeMalformed, len(certRaw))
	}
	if len(certRaw) > int(^uint16(0)) {
		return nil, [32]byte{}, fmt.Errorf("%w: cert too large", ErrHandshakeMalformed)
	}

	noSigLen := 2 + 8 + 16 + 8 + 32 + 2 + len(certRaw)
	noSig := make([]byte, noSigLen)
	i := 0
	binary.BigEndian.PutUint16(noSig[i:i+2], flags)
	i += 2
	binary.BigEndian.PutUint64(noSig[i:i+8], timestamp)
	i += 8
	copy(noSig[i:i+16], nonce[:])
	i += 16
	copy(noSig[i:i+8], userHash[:])
	i += 8
	copy(noSig[i:i+32], eph[:])
	i += 32
	binary.BigEndian.PutUint16(noSig[i:i+2], uint16(len(certRaw)))
	i += 2
	copy(noSig[i:i+len(certRaw)], certRaw)
	i += len(certRaw)
	if i != len(noSig) {
		return nil, [32]byte{}, fmt.Errorf("%w: internal marshal mismatch", ErrHandshakeMalformed)
	}

	sig := ed25519.Sign(priv, noSig)
	body := append(noSig, sig...)
	return body, sha256.Sum256(noSig), nil
}

type parsedServerHello struct {
	Flags        uint16
	Timestamp    uint64
	Nonce        [16]byte
	EchoNonce    [16]byte
	Ephemeral    [32]byte
	CertRaw      []byte
	Cert         *Cert
	ClientHelloH [32]byte
	Signature    []byte
	BodyNoSig    []byte
	BodyHash32   [32]byte
}

func parseServerHello(body []byte) (*parsedServerHello, error) {
	if len(body) < serverHelloMinSize {
		return nil, fmt.Errorf("%w: server hello too short", ErrHandshakeMalformed)
	}
	i := 0
	flags := binary.BigEndian.Uint16(body[i : i+2])
	i += 2
	ts := binary.BigEndian.Uint64(body[i : i+8])
	i += 8
	var nonceS [16]byte
	copy(nonceS[:], body[i:i+16])
	i += 16
	var echoNonceC [16]byte
	copy(echoNonceC[:], body[i:i+16])
	i += 16
	var eph [32]byte
	copy(eph[:], body[i:i+32])
	i += 32
	certLen := int(binary.BigEndian.Uint16(body[i : i+2]))
	i += 2
	if certLen <= 0 || certLen > maxCertLen {
		return nil, fmt.Errorf("%w: invalid cert len %d", ErrHandshakeMalformed, certLen)
	}
	if len(body) < i+certLen+32+ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: truncated", ErrHandshakeMalformed)
	}
	certRaw := body[i : i+certLen]
	i += certLen
	var clientHelloH [32]byte
	copy(clientHelloH[:], body[i:i+32])
	i += 32
	sig := body[i : i+ed25519.SignatureSize]
	i += ed25519.SignatureSize
	if i != len(body) {
		return nil, fmt.Errorf("%w: trailing bytes", ErrHandshakeMalformed)
	}
	cert, err := ParseCert(certRaw)
	if err != nil {
		return nil, err
	}

	noSig := body[:len(body)-ed25519.SignatureSize]
	h := sha256.Sum256(noSig)
	return &parsedServerHello{
		Flags:        flags,
		Timestamp:    ts,
		Nonce:        nonceS,
		EchoNonce:    echoNonceC,
		Ephemeral:    eph,
		CertRaw:      certRaw,
		Cert:         cert,
		ClientHelloH: clientHelloH,
		Signature:    sig,
		BodyNoSig:    noSig,
		BodyHash32:   h,
	}, nil
}

func buildServerHello(flags uint16, timestamp uint64, nonceS [16]byte, echoNonceC [16]byte, eph [32]byte, certRaw []byte, clientHelloHash [32]byte, priv ed25519.PrivateKey) ([]byte, [32]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, [32]byte{}, fmt.Errorf("%w: invalid server private key", ErrAuthFailed)
	}
	if len(certRaw) <= 0 || len(certRaw) > maxCertLen {
		return nil, [32]byte{}, fmt.Errorf("%w: invalid cert len %d", ErrHandshakeMalformed, len(certRaw))
	}
	noSigLen := 2 + 8 + 16 + 16 + 32 + 2 + len(certRaw) + 32
	noSig := make([]byte, noSigLen)
	i := 0
	binary.BigEndian.PutUint16(noSig[i:i+2], flags)
	i += 2
	binary.BigEndian.PutUint64(noSig[i:i+8], timestamp)
	i += 8
	copy(noSig[i:i+16], nonceS[:])
	i += 16
	copy(noSig[i:i+16], echoNonceC[:])
	i += 16
	copy(noSig[i:i+32], eph[:])
	i += 32
	binary.BigEndian.PutUint16(noSig[i:i+2], uint16(len(certRaw)))
	i += 2
	copy(noSig[i:i+len(certRaw)], certRaw)
	i += len(certRaw)
	copy(noSig[i:i+32], clientHelloHash[:])
	i += 32
	if i != len(noSig) {
		return nil, [32]byte{}, fmt.Errorf("%w: internal marshal mismatch", ErrHandshakeMalformed)
	}

	sig := ed25519.Sign(priv, noSig)
	body := append(noSig, sig...)
	return body, sha256.Sum256(noSig), nil
}

type parsedClientFinish struct {
	ClientHelloH [32]byte
	ServerHelloH [32]byte
	MAC16        [16]byte
}

func parseClientFinish(body []byte) (*parsedClientFinish, error) {
	if len(body) != clientFinishSize {
		return nil, fmt.Errorf("%w: client finish size mismatch %d", ErrHandshakeMalformed, len(body))
	}
	var out parsedClientFinish
	copy(out.ClientHelloH[:], body[0:32])
	copy(out.ServerHelloH[:], body[32:64])
	copy(out.MAC16[:], body[64:80])
	return &out, nil
}
