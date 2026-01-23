package iotbci

import (
	"bytes"
	"net"
	"testing"
)

func TestNewAEAD_AES128GCM(t *testing.T) {
	t.Parallel()

	aead, err := newAEAD(AEADAES128GCM, bytes.Repeat([]byte{0x11}, 16))
	if err != nil {
		t.Fatalf("newAEAD: %v", err)
	}
	if aead.NonceSize() != 12 {
		t.Fatalf("unexpected nonce size: %d", aead.NonceSize())
	}
	if _, err := newAEAD(AEADAES128GCM, bytes.Repeat([]byte{0x11}, 15)); err == nil {
		t.Fatalf("expected short key error")
	}
	if _, err := newAEAD(AEADMethod("bogus"), bytes.Repeat([]byte{0x11}, 32)); err == nil {
		t.Fatalf("expected unsupported aead error")
	}
}

func TestNewRecordConn_NoneReturnsBase(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	c, err := NewRecordConn(a, AEADNone, nil, nil, [4]byte{}, [4]byte{})
	if err != nil {
		t.Fatalf("NewRecordConn: %v", err)
	}
	if c != a {
		t.Fatalf("expected base conn passthrough for AEADNone")
	}
}
