package mux

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestSession_Echo(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		sess, err := Accept(serverConn, Config{})
		if err != nil {
			return
		}
		for {
			st, _, err := sess.AcceptStream(ctx)
			if err != nil {
				_ = sess.Close()
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(st)
		}
	}()

	mux, err := Dial(clientConn, Config{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer mux.Close()

	stream, err := mux.OpenStream([]byte("chan-1"))
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stream.Close()

	msg := []byte("hello mux")
	if _, err := stream.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: got %q want %q", buf, msg)
	}

	_ = mux.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("server did not exit: %v", ctx.Err())
	}
}

func TestSession_QueueLimit(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	cfg := Config{MaxQueuedBytesPerStream: 64, MaxQueuedBytesTotal: 64, MaxDataPayload: 1024}

	sessSCh := make(chan *Session, 1)
	sessSErr := make(chan error, 1)
	go func() {
		sessS, err := Accept(serverConn, cfg)
		if err != nil {
			sessSErr <- err
			return
		}
		sessSCh <- sessS
	}()

	sessC, err := Dial(clientConn, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer sessC.Close()

	var sessS *Session
	select {
	case err := <-sessSErr:
		t.Fatalf("Accept: %v", err)
	case sessS = <-sessSCh:
	}
	defer sessS.Close()

	// Server: accept but do not read -> client writes should eventually trigger backpressure handling
	// (receiver side queue limit -> reset).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stC, err := sessC.OpenStream(nil)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer stC.Close()

	stSConn, _, err := sessS.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	defer stSConn.Close()

	// Push enough data to overflow receiver queued bytes.
	_, _ = stC.Write(make([]byte, 256))

	// The server side should be reset/closed soon.
	readDone := make(chan error, 1)
	go func() {
		one := make([]byte, 1)
		_, rErr := stSConn.Read(one)
		readDone <- rErr
	}()
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatalf("expected stream error due to queue limit")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for reset")
	}
}
