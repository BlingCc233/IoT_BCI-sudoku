package iotbci

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/obfs/sudoku"
)

func ClientHandshake(ctx context.Context, rawConn net.Conn, opts *ClientOptions) (net.Conn, *HandshakeMeta, error) {
	if rawConn == nil {
		return nil, nil, fmt.Errorf("nil conn")
	}
	if opts == nil {
		return nil, nil, fmt.Errorf("nil options")
	}
	opts.setDefaults()

	if err := validateIdentity(opts.Identity); err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	psk := opts.Security.PSK
	if opts.Security.HandshakeAEAD != AEADNone && psk == "" {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("%w: handshake AEAD requires PSK", ErrAuthFailed)
	}
	obfsKey := opts.Obfs.Key
	if obfsKey == "" {
		obfsKey = psk
	}
	if obfsKey == "" {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("%w: missing obfs key/psk", ErrAuthFailed)
	}

	ts, err := sudoku.NewTableSet(obfsKey, opts.Obfs.ASCII, opts.Obfs.CustomTables)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	tables := ts.Candidates()
	if len(tables) == 0 {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("no tables configured")
	}
	table := tables[0]
	if len(tables) > 1 {
		var b [1]byte
		if _, err := io.ReadFull(opts.Rand, b[:]); err != nil {
			_ = rawConn.Close()
			return nil, nil, err
		}
		table = tables[int(b[0])%len(tables)]
	}

	obfsConn := buildObfsConnForClient(rawConn, table, opts.Obfs)

	// Handshake channel (optionally PSK-protected).
	hsConn := obfsConn
	if opts.Security.HandshakeAEAD != AEADNone {
		c2sKey, s2cKey, c2sSalt, s2cSalt := DerivePSKHandshakeKeys(psk)
		c, err := NewRecordConn(obfsConn, opts.Security.HandshakeAEAD, c2sKey[:], s2cKey[:], c2sSalt, s2cSalt)
		if err != nil {
			_ = rawConn.Close()
			return nil, nil, err
		}
		hsConn = c
	}

	deadline := time.Now().Add(opts.Security.HandshakeTimeout)
	_ = rawConn.SetDeadline(deadline)
	defer func() { _ = rawConn.SetDeadline(time.Time{}) }()

	select {
	case <-ctx.Done():
		_ = rawConn.Close()
		return nil, nil, ctx.Err()
	default:
	}

	flags, err := encodeFlags(opts.Security.SessionAEAD, opts.Obfs.EnablePureDownlink)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	curve := ecdh.X25519()
	clientEph, err := curve.GenerateKey(opts.Rand)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	var clientEphPub [32]byte
	copy(clientEphPub[:], clientEph.PublicKey().Bytes())

	var nonceC [16]byte
	if _, err := io.ReadFull(opts.Rand, nonceC[:]); err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	now := time.Now()
	userHash := userHashFromPrivateKey(opts.Identity.LocalPrivateKey)
	certRaw, err := opts.Identity.LocalCert.MarshalBinary()
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	body, clientHelloHash, err := buildClientHello(
		flags,
		uint64(now.Unix()),
		nonceC,
		userHash,
		clientEphPub,
		certRaw,
		opts.Identity.LocalPrivateKey,
	)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	if err := writeHandshakeFrame(hsConn, hsMsgClientHello, body); err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	msgType, serverBody, err := readHandshakeFrame(hsConn, opts.Security.MaxHandshakeSize)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	if msgType != hsMsgServerHello {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("%w: expected server hello, got %d", ErrProtocolViolation, msgType)
	}

	sHello, err := parseServerHello(serverBody)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	if sHello.ClientHelloH != clientHelloHash {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("%w: client hello hash mismatch", ErrAuthFailed)
	}

	if absDuration(time.Since(time.Unix(int64(sHello.Timestamp), 0))) > opts.Security.TimeSkew {
		_ = rawConn.Close()
		return nil, nil, ErrTimeSkew
	}
	if sHello.EchoNonce != nonceC {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("%w: nonce mismatch", ErrAuthFailed)
	}

	peerPub, err := verifyPeerCert(opts.Identity, sHello.Cert, now, nil)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	if !ed25519.Verify(peerPub, sHello.BodyNoSig, sHello.Signature) {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("%w: server signature mismatch", ErrAuthFailed)
	}

	peerAEAD, peerPureDownlink, err := decodeFlags(sHello.Flags)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	if peerAEAD != opts.Security.SessionAEAD || peerPureDownlink != opts.Obfs.EnablePureDownlink {
		_ = rawConn.Close()
		return nil, nil, fmt.Errorf("%w: option mismatch", ErrProtocolViolation)
	}

	peerEphPub, err := curve.NewPublicKey(sHello.Ephemeral[:])
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	sharedSecret, err := clientEph.ECDH(peerEphPub)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	transcriptHash := sha256.Sum256(append(clientHelloHash[:], sHello.BodyHash32[:]...))
	ks, err := deriveSessionKeySchedule(sharedSecret, transcriptHash)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	mac := finishMAC(ks.confirmK, clientHelloHash, sHello.BodyHash32)
	finishBody := make([]byte, 0, clientFinishSize)
	finishBody = append(finishBody, clientHelloHash[:]...)
	finishBody = append(finishBody, sHello.BodyHash32[:]...)
	finishBody = append(finishBody, mac[:]...)
	if err := writeHandshakeFrame(hsConn, hsMsgClientFinish, finishBody); err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	// Switch to forward-secure session keys.
	if opts.Security.SessionAEAD == AEADNone {
		return obfsConn, &HandshakeMeta{
			UserHash:    "",
			PeerSubject: sHello.Cert.Subject,
			PeerSerial:  sHello.Cert.Serial,
		}, nil
	}
	sessionConn, err := NewRecordConn(obfsConn, opts.Security.SessionAEAD, ks.c2sKey[:], ks.s2cKey[:], ks.c2sSalt4, ks.s2cSalt4)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}

	return sessionConn, &HandshakeMeta{
		UserHash:    "",
		PeerSubject: sHello.Cert.Subject,
		PeerSerial:  sHello.Cert.Serial,
	}, nil
}

func validateIdentity(id IdentityOptions) error {
	if id.LocalCert == nil {
		return fmt.Errorf("%w: missing local cert", ErrAuthFailed)
	}
	if len(id.LocalPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: invalid local private key", ErrAuthFailed)
	}
	pub := id.LocalPrivateKey.Public().(ed25519.PublicKey)
	if !bytesEq32(pub, id.LocalCert.PublicKey) {
		return fmt.Errorf("%w: private key does not match certificate public key", ErrAuthFailed)
	}
	if len(id.MasterPublicKey) == 0 && len(id.PeerPublicKey) == 0 {
		return fmt.Errorf("%w: missing trust anchor (master public key or peer pin)", ErrAuthFailed)
	}
	return nil
}

func verifyPeerCert(id IdentityOptions, cert *Cert, now time.Time, revocation *RevocationList) (ed25519.PublicKey, error) {
	if cert == nil {
		return nil, fmt.Errorf("%w: missing peer cert", ErrAuthFailed)
	}
	if len(id.MasterPublicKey) != 0 {
		if err := cert.Verify(id.MasterPublicKey, now, revocation); err != nil {
			return nil, err
		}
	}
	if len(id.PeerPublicKey) != 0 && !bytesEq32(id.PeerPublicKey, cert.PublicKey) {
		return nil, fmt.Errorf("%w: peer pin mismatch", ErrAuthFailed)
	}
	return cert.PublicKey, nil
}

func bytesEq32(a []byte, b []byte) bool {
	if len(a) != 32 || len(b) != 32 {
		return false
	}
	var x byte
	for i := 0; i < 32; i++ {
		x |= a[i] ^ b[i]
	}
	return x == 0
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
