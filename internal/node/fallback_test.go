package node

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeRecordedConn struct {
	net.Conn
	data []byte
}

func (f *fakeRecordedConn) GetBufferedAndRecorded() []byte { return append([]byte(nil), f.data...) }

func TestHandleSuspicious_FallbackForwardsRecordedAndLiveBytes(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var (
		gotMu sync.Mutex
		got   bytes.Buffer
	)

	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))

		buf := make([]byte, 16)
		for got.Len() < len("BADHELLO") {
			n, err := c.Read(buf)
			if n > 0 {
				gotMu.Lock()
				got.Write(buf[:n])
				gotMu.Unlock()
			}
			if err != nil {
				serverDone <- err
				return
			}
		}
		_, _ = c.Write([]byte("ACK"))
		serverDone <- nil
	}()

	rawA, rawB := net.Pipe()
	defer rawA.Close()
	defer rawB.Close()

	wrapper := &fakeRecordedConn{Conn: rawA, data: []byte("BAD")}
	HandleSuspicious(wrapper, rawA, ln.Addr().String(), "fallback")

	_ = rawB.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := rawB.Write([]byte("HELLO")); err != nil {
		t.Fatal(err)
	}

	_ = rawB.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 3)
	if _, err := io.ReadFull(rawB, resp); err != nil {
		t.Fatal(err)
	}
	if string(resp) != "ACK" {
		t.Fatalf("unexpected resp: %q", string(resp))
	}

	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}

	gotMu.Lock()
	defer gotMu.Unlock()
	if got.String() != "BADHELLO" {
		t.Fatalf("unexpected forwarded bytes: %q", got.String())
	}
}

func TestHandleSuspicious_SilentAction(t *testing.T) {
	t.Parallel()

	old := silentHoldDuration
	silentHoldDuration = 0
	t.Cleanup(func() { silentHoldDuration = old })

	rawA, rawB := net.Pipe()
	defer rawA.Close()
	defer rawB.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		HandleSuspicious(nil, rawA, "", "silent")
	}()

	// Unblock io.Copy by closing the other side.
	_ = rawB.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("silent action did not return")
	}
}
