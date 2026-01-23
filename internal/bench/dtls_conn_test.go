package bench

import (
	"net"
	"testing"
	"time"
)

func TestPacketConnConn_Methods(t *testing.T) {
	t.Parallel()

	serverPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer serverPC.Close()

	raddr := serverPC.LocalAddr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer clientConn.Close()

	c := newPacketConnConn(serverPC)
	if c.LocalAddr() == nil {
		t.Fatalf("expected LocalAddr")
	}
	if c.RemoteAddr() != nil {
		t.Fatalf("expected nil RemoteAddr before any read")
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Millisecond))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))

	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatalf("expected error before remote is set")
	}

	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("unexpected read: %q", string(buf[:n]))
	}
	if c.RemoteAddr() == nil {
		t.Fatalf("expected RemoteAddr after read")
	}

	if _, err := c.Write([]byte("pong")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = clientConn.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("unexpected client read: %q", string(buf[:n]))
	}
	_ = c.Close()
}
