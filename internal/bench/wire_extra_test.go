package bench

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestCountingConn_Stats(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	stats := &WireStats{}
	c := WrapConn(a, stats).(*CountingConn)
	if c.Stats() != stats {
		t.Fatalf("Stats pointer mismatch")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 3)
		_, _ = io.ReadFull(b, buf)
	}()

	if _, err := c.Write([]byte("abc")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	<-done
}

func TestCountingPacketConn_Stats(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	stats := &WireStats{}
	c := WrapPacketConn(pc, stats).(*CountingPacketConn)
	if c.Stats() != stats {
		t.Fatalf("Stats pointer mismatch")
	}
}
