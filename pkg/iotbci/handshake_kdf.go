package iotbci

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

type sessionKeySchedule struct {
	c2sKey   [32]byte
	s2cKey   [32]byte
	c2sSalt4 [4]byte
	s2cSalt4 [4]byte
	confirmK [32]byte
}

func deriveSessionKeySchedule(sharedSecret []byte, transcriptHash [32]byte) (sessionKeySchedule, error) {
	var ks sessionKeySchedule
	r := hkdf.New(sha256.New, sharedSecret, transcriptHash[:], []byte("iotbci-sudoku-session-v1"))
	if _, err := io.ReadFull(r, ks.c2sKey[:]); err != nil {
		return ks, err
	}
	if _, err := io.ReadFull(r, ks.s2cKey[:]); err != nil {
		return ks, err
	}
	if _, err := io.ReadFull(r, ks.c2sSalt4[:]); err != nil {
		return ks, err
	}
	if _, err := io.ReadFull(r, ks.s2cSalt4[:]); err != nil {
		return ks, err
	}
	if _, err := io.ReadFull(r, ks.confirmK[:]); err != nil {
		return ks, err
	}
	return ks, nil
}

func finishMAC(confirmKey [32]byte, clientHelloHash [32]byte, serverHelloHash [32]byte) [16]byte {
	m := hmac.New(sha256.New, confirmKey[:])
	_, _ = m.Write(clientHelloHash[:])
	_, _ = m.Write(serverHelloHash[:])
	sum := m.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func verifyFinishMAC(confirmKey [32]byte, clientHelloHash [32]byte, serverHelloHash [32]byte, mac16 [16]byte) error {
	want := finishMAC(confirmKey, clientHelloHash, serverHelloHash)
	if !hmac.Equal(want[:], mac16[:]) {
		return fmt.Errorf("%w: finish mac mismatch", ErrAuthFailed)
	}
	return nil
}
