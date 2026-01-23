package iotbci

import "testing"

func TestAEADIDMapping(t *testing.T) {
	t.Parallel()

	id, err := aeadToID(AEADNone)
	if err != nil || id != 0 {
		t.Fatalf("AEADNone: id=%d err=%v", id, err)
	}
	id, err = aeadToID(AEADAES128GCM)
	if err != nil || id != 1 {
		t.Fatalf("AEADAES128GCM: id=%d err=%v", id, err)
	}
	id, err = aeadToID(AEADChaCha20Poly1305)
	if err != nil || id != 2 {
		t.Fatalf("AEADChaCha20Poly1305: id=%d err=%v", id, err)
	}
	if _, err := aeadToID(AEADMethod("unknown")); err == nil {
		t.Fatalf("expected error for unknown aead")
	}

	m, err := idToAEAD(0)
	if err != nil || m != AEADNone {
		t.Fatalf("id 0: %q %v", m, err)
	}
	m, err = idToAEAD(1)
	if err != nil || m != AEADAES128GCM {
		t.Fatalf("id 1: %q %v", m, err)
	}
	m, err = idToAEAD(2)
	if err != nil || m != AEADChaCha20Poly1305 {
		t.Fatalf("id 2: %q %v", m, err)
	}
	if _, err := idToAEAD(999); err == nil {
		t.Fatalf("expected error for unknown aead id")
	}
}
