package iotbci

import (
	"bytes"
	"net"
	"testing"
)

type closeHookConn struct {
	net.Conn
	closeReadCalled  bool
	closeWriteCalled bool
}

func (c *closeHookConn) CloseRead() error {
	c.closeReadCalled = true
	return nil
}

func (c *closeHookConn) CloseWrite() error {
	c.closeWriteCalled = true
	return nil
}

func TestDirectionalConn_CloseFallsBackToBaseConn(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	base := &closeHookConn{Conn: a}
	c := newDirectionalConn(base, bytes.NewReader([]byte("in")), &bytes.Buffer{}).(*directionalConn)

	_ = c.CloseRead()
	_ = c.CloseWrite()
	if !base.closeReadCalled || !base.closeWriteCalled {
		t.Fatalf("expected CloseRead/CloseWrite to fall back to base conn")
	}
	_ = c.Close()
}
