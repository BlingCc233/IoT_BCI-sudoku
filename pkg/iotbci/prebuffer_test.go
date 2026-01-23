package iotbci

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestPreBufferedConn_Read(t *testing.T) {
	t.Parallel()

	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	pre := []byte("hello-")
	conn := NewPreBufferedConn(sRaw, pre)

	go func() {
		_, _ = cRaw.Write([]byte("world"))
	}()

	buf := make([]byte, 11)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello-world" {
		t.Fatalf("got %q", string(buf))
	}
}

func TestPreBufferedConn_PassThroughCloseWriteRead(t *testing.T) {
	t.Parallel()

	base, _ := net.Pipe()
	defer base.Close()

	conn := NewPreBufferedConn(base, []byte("x"))
	p, ok := conn.(*PreBufferedConn)
	if !ok {
		t.Fatalf("expected PreBufferedConn wrapper")
	}
	if err := p.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := p.CloseRead(); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyConn(t *testing.T) {
	t.Parallel()

	rc := &readOnlyConn{Reader: bytes.NewReader([]byte("abc"))}
	_ = rc.LocalAddr()
	_ = rc.RemoteAddr()
	b := make([]byte, 3)
	if _, err := io.ReadFull(rc, b); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Write([]byte("x")); err == nil {
		t.Fatalf("expected write error")
	}
	_ = rc.SetDeadline(time.Now())
	_ = rc.SetReadDeadline(time.Now())
	_ = rc.SetWriteDeadline(time.Now())
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
}
