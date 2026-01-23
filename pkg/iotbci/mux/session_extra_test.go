package mux

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestSession_Closed_Nil(t *testing.T) {
	t.Parallel()

	var s *Session
	select {
	case <-s.Closed():
	default:
		t.Fatalf("expected closed channel for nil session")
	}
}

func TestStream_CloseRemote_DrainsBufferedThenEOF(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cRaw, sRaw := net.Pipe()
	defer cRaw.Close()
	defer sRaw.Close()

	serverErr := make(chan error, 1)
	go func() {
		sess, err := Accept(sRaw, Config{})
		if err != nil {
			serverErr <- err
			return
		}
		defer sess.Close()

		st, _, err := sess.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		msg := []byte("hello")
		if _, err := st.Write(msg); err != nil {
			serverErr <- err
			return
		}
		_ = st.Close()
		serverErr <- nil
	}()

	sess, err := Dial(cRaw, Config{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer sess.Close()

	stream, err := sess.OpenStream(nil)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	st := stream.(*Stream)

	_ = st.LocalAddr()
	_ = st.RemoteAddr()
	_ = st.SetDeadline(time.Now().Add(10 * time.Millisecond))
	_ = st.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	_ = st.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))

	buf := make([]byte, 5)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("unexpected payload: %q", string(buf))
	}
	one := make([]byte, 1)
	_, err = st.Read(one)
	if err != io.EOF {
		t.Fatalf("expected EOF after draining, got %v", err)
	}
	_ = st.CloseWrite()
	_ = st.CloseRead()

	if err := <-serverErr; err != nil && err != io.EOF {
		t.Fatalf("server: %v", err)
	}
}
