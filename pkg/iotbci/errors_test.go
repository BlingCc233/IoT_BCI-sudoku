package iotbci

import (
	"errors"
	"net"
	"testing"
)

func TestSuspiciousError(t *testing.T) {
	t.Parallel()

	inner := errors.New("bad")
	c1, _ := net.Pipe()
	defer c1.Close()
	e := &SuspiciousError{Err: inner, Conn: c1}
	if e.Error() == "" {
		t.Fatalf("expected non-empty error string")
	}
	if !errors.Is(e, inner) {
		t.Fatalf("expected unwrap to work")
	}
}
