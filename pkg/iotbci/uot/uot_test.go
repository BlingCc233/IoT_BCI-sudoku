package uot

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestDatagramRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteDatagram(&buf, "addr-1", []byte("hello")); err != nil {
		t.Fatalf("WriteDatagram: %v", err)
	}
	addr, payload, err := ReadDatagram(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadDatagram: %v", err)
	}
	if addr != "addr-1" || string(payload) != "hello" {
		t.Fatalf("mismatch: addr=%q payload=%q", addr, payload)
	}
}

func TestPacketConnRoundTrip(t *testing.T) {
	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	s := NewPacketConn(sRaw)
	c := NewPacketConn(cRaw)

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		n, addr, err := s.ReadFrom(buf)
		if err != nil {
			return
		}
		if addr.String() != "dst" || string(buf[:n]) != "ping" {
			return
		}
		_, _ = s.WriteTo([]byte("pong"), Addr("dst"))
	}()

	if _, err := c.WriteTo([]byte("ping"), Addr("dst")); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("want pong, got %q", buf[:n])
	}
	<-done
}

func TestPacketConn_ShortBuffer(t *testing.T) {
	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	s := NewPacketConn(sRaw)
	c := NewPacketConn(cRaw)

	go func() {
		_, _ = c.WriteTo(bytes.Repeat([]byte{0xAA}, 64), Addr("dst"))
	}()

	buf := make([]byte, 8)
	_, _, err := s.ReadFrom(buf)
	if err != io.ErrShortBuffer {
		t.Fatalf("expected ErrShortBuffer, got %v", err)
	}
}

func TestPrefaceAndAddr(t *testing.T) {
	var buf bytes.Buffer
	if err := WritePreface(&buf); err != nil {
		t.Fatalf("WritePreface: %v", err)
	}
	if err := ReadPreface(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("ReadPreface: %v", err)
	}
	if Addr("x").Network() != "uot" {
		t.Fatalf("unexpected network")
	}
}

func TestPacketConn_MiscMethods(t *testing.T) {
	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	pc := NewPacketConn(sRaw)
	_ = pc.LocalAddr()
	_ = pc.SetDeadline(time.Now().Add(10 * time.Millisecond))
	_ = pc.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_ = pc.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if err := pc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
