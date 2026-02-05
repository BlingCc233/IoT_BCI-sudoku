package iotbci

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/obfs/sudoku"
)

func ServerHandshake(ctx context.Context, rawConn net.Conn, opts *ServerOptions) (net.Conn, *HandshakeMeta, error) {
	if rawConn == nil {
		return nil, nil, fmt.Errorf("nil conn")
	}
	if opts == nil {
		_ = rawConn.Close()
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

	bufReader := bufio.NewReader(rawConn)
	_ = rawConn.SetReadDeadline(time.Now().Add(opts.Security.HandshakeTimeout))

	selectedTable, preRead, selErr := selectTableByProbe(bufReader, opts.Obfs, opts.Security.HandshakeAEAD, psk, tables, opts.Security.MaxHandshakeSize)
	_ = rawConn.SetReadDeadline(time.Time{})
	if selErr != nil {
		tail, _ := drainBuffered(bufReader)
		preRead = append(preRead, tail...)
		return nil, nil, &SuspiciousError{
			Err:  selErr,
			Conn: &recordedConn{Conn: rawConn, recorded: preRead},
		}
	}

	baseConn := NewPreBufferedConn(rawConn, preRead)
	uplinkSudoku, obfsConn := buildObfsConnForServer(baseConn, selectedTable, opts.Obfs, true)

	// Handshake channel (optionally PSK-protected).
	hsConn := obfsConn
	if opts.Security.HandshakeAEAD != AEADNone {
		c2sKey, s2cKey, c2sSalt, s2cSalt := DerivePSKHandshakeKeys(psk)
		c, err := NewRecordConn(obfsConn, opts.Security.HandshakeAEAD, s2cKey[:], c2sKey[:], s2cSalt, c2sSalt)
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

	msgType, clientBody, err := readHandshakeFrame(hsConn, opts.Security.MaxHandshakeSize)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	if msgType != hsMsgClientHello {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("%w: expected client hello, got %d", ErrProtocolViolation, msgType), Conn: uplinkSudoku}
	}
	cHello, err := parseClientHello(clientBody)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}

	now := time.Now()
	clientTS := time.Unix(int64(cHello.Timestamp), 0)
	if absDuration(now.Sub(clientTS)) > opts.Security.TimeSkew {
		return nil, nil, &SuspiciousError{Err: ErrTimeSkew, Conn: uplinkSudoku}
	}

	peerAEAD, peerPureDownlink, peerPackedUplink, err := decodeFlags(cHello.Flags)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	if peerAEAD != opts.Security.SessionAEAD ||
		peerPureDownlink != opts.Obfs.EnablePureDownlink ||
		peerPackedUplink != opts.Obfs.EnablePackedUplink {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("%w: option mismatch", ErrProtocolViolation), Conn: uplinkSudoku}
	}

	clientPub, err := verifyPeerCert(opts.Identity, cHello.Cert, now, opts.Revocation)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	if !ed25519.Verify(clientPub, cHello.BodyNoSig, cHello.Signature) {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("%w: client signature mismatch", ErrAuthFailed), Conn: uplinkSudoku}
	}

	// Replay defense (commit only after authentication).
	token := make([]byte, 0, 8+16+8)
	token = append(token, cHello.UserHash[:]...)
	token = append(token, cHello.Nonce[:]...)
	var serialBuf [8]byte
	binary.BigEndian.PutUint64(serialBuf[:], cHello.Cert.Serial)
	token = append(token, serialBuf[:]...)
	if opts.Replay.SeenOrAdd(token, now) {
		return nil, nil, &SuspiciousError{Err: ErrReplayDetected, Conn: uplinkSudoku}
	}

	// Server response.
	flags, err := encodeFlags(opts.Security.SessionAEAD, opts.Obfs.EnablePureDownlink, opts.Obfs.EnablePackedUplink)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}

	curve := ecdh.X25519()
	serverEph, err := curve.GenerateKey(opts.Rand)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	var serverEphPub [32]byte
	copy(serverEphPub[:], serverEph.PublicKey().Bytes())

	var nonceS [16]byte
	if _, err := io.ReadFull(opts.Rand, nonceS[:]); err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}

	serverCertRaw, err := opts.Identity.LocalCert.MarshalBinary()
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	serverBody, serverHelloHash, err := buildServerHello(
		flags,
		uint64(now.Unix()),
		nonceS,
		cHello.Nonce,
		serverEphPub,
		serverCertRaw,
		cHello.BodyHash32,
		opts.Identity.LocalPrivateKey,
	)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	if err := writeHandshakeFrame(hsConn, hsMsgServerHello, serverBody); err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}

	clientEphPub, err := curve.NewPublicKey(cHello.Ephemeral[:])
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	sharedSecret, err := serverEph.ECDH(clientEphPub)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}

	transcriptHash := sha256.Sum256(append(cHello.BodyHash32[:], serverHelloHash[:]...))
	ks, err := deriveSessionKeySchedule(sharedSecret, transcriptHash)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}

	msgType, finishBody, err := readHandshakeFrame(hsConn, opts.Security.MaxHandshakeSize)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	if msgType != hsMsgClientFinish {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("%w: expected client finish, got %d", ErrProtocolViolation, msgType), Conn: uplinkSudoku}
	}
	finish, err := parseClientFinish(finishBody)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	if finish.ClientHelloH != cHello.BodyHash32 || finish.ServerHelloH != serverHelloHash {
		return nil, nil, &SuspiciousError{Err: fmt.Errorf("%w: finish hash mismatch", ErrAuthFailed), Conn: uplinkSudoku}
	}
	if err := verifyFinishMAC(ks.confirmK, cHello.BodyHash32, serverHelloHash, finish.MAC16); err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}

	uplinkSudoku.StopRecording()

	// Switch to forward-secure session keys.
	if opts.Security.SessionAEAD == AEADNone {
		return obfsConn, &HandshakeMeta{
			UserHash:    hex.EncodeToString(cHello.UserHash[:]),
			PeerSubject: cHello.Cert.Subject,
			PeerSerial:  cHello.Cert.Serial,
		}, nil
	}
	sessionConn, err := NewRecordConn(obfsConn, opts.Security.SessionAEAD, ks.s2cKey[:], ks.c2sKey[:], ks.s2cSalt4, ks.c2sSalt4)
	if err != nil {
		return nil, nil, &SuspiciousError{Err: err, Conn: uplinkSudoku}
	}
	return sessionConn, &HandshakeMeta{
		UserHash:    hex.EncodeToString(cHello.UserHash[:]),
		PeerSubject: cHello.Cert.Subject,
		PeerSerial:  cHello.Cert.Serial,
	}, nil
}

type recordedConn struct {
	net.Conn
	recorded []byte
}

func (r *recordedConn) CloseWrite() error {
	if r == nil || r.Conn == nil {
		return nil
	}
	if cw, ok := r.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (r *recordedConn) CloseRead() error {
	if r == nil || r.Conn == nil {
		return nil
	}
	if cr, ok := r.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (r *recordedConn) GetBufferedAndRecorded() []byte { return r.recorded }
