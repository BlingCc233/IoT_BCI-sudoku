package iotbci

import (
	"bytes"
	"net"
	"testing"
)

type cwcrConn struct {
	net.Conn
	closeReadCalled  bool
	closeWriteCalled bool
}

func (c *cwcrConn) CloseRead() error {
	c.closeReadCalled = true
	return nil
}

func (c *cwcrConn) CloseWrite() error {
	c.closeWriteCalled = true
	return nil
}

func TestRecordedConn_CloseReadWriteAndBuffer(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	base := &cwcrConn{Conn: a}
	rc := &recordedConn{Conn: base, recorded: []byte{0x01, 0x02, 0x03}}

	if got := rc.GetBufferedAndRecorded(); !bytes.Equal(got, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("GetBufferedAndRecorded mismatch: %v", got)
	}
	_ = rc.CloseWrite()
	_ = rc.CloseRead()
	if !base.closeWriteCalled || !base.closeReadCalled {
		t.Fatalf("expected CloseWrite/CloseRead delegated to base conn")
	}

	var nilRC *recordedConn
	_ = nilRC.CloseWrite()
	_ = nilRC.CloseRead()

	empty := &recordedConn{}
	_ = empty.CloseWrite()
	_ = empty.CloseRead()
}
