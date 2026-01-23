package iotbci

import (
	"context"
	"crypto/sha256"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRecordConn_ConcurrentReadWrite(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	c2sKey, s2cKey, c2sSalt, s2cSalt := DerivePSKHandshakeKeys("test-psk")

	sConn, err := NewRecordConn(sRaw, AEADChaCha20Poly1305, s2cKey[:], c2sKey[:], s2cSalt, c2sSalt)
	if err != nil {
		t.Fatal(err)
	}
	cConn, err := NewRecordConn(cRaw, AEADChaCha20Poly1305, c2sKey[:], s2cKey[:], c2sSalt, s2cSalt)
	if err != nil {
		t.Fatal(err)
	}

	c2s := make([]byte, 128*1024)
	s2c := make([]byte, 128*1024)
	rng := rand.New(rand.NewSource(1))
	_, _ = rng.Read(c2s)
	_, _ = rng.Read(s2c)

	wantC2S := sha256.Sum256(c2s)
	wantS2C := sha256.Sum256(s2c)

	var wg sync.WaitGroup
	wg.Add(4)

	// Server read (inbound from client).
	sReadErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(c2s))
		_ = sConn.SetReadDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.ReadFull(sConn, buf); err != nil {
			sReadErr <- err
			return
		}
		if sha256.Sum256(buf) != wantC2S {
			sReadErr <- io.ErrUnexpectedEOF
			return
		}
		sReadErr <- nil
	}()

	// Server write (outbound to client).
	sWriteErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		_ = sConn.SetWriteDeadline(time.Now().Add(4 * time.Second))
		sWriteErr <- writeChunks(ctx, sConn, s2c, 97)
	}()

	// Client read (inbound from server).
	cReadErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		buf := make([]byte, len(s2c))
		_ = cConn.SetReadDeadline(time.Now().Add(4 * time.Second))
		if _, err := io.ReadFull(cConn, buf); err != nil {
			cReadErr <- err
			return
		}
		if sha256.Sum256(buf) != wantS2C {
			cReadErr <- io.ErrUnexpectedEOF
			return
		}
		cReadErr <- nil
	}()

	// Client write (outbound to server).
	cWriteErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		_ = cConn.SetWriteDeadline(time.Now().Add(4 * time.Second))
		cWriteErr <- writeChunks(ctx, cConn, c2s, 113)
	}()

	wg.Wait()

	if err := <-sReadErr; err != nil {
		t.Fatal(err)
	}
	if err := <-sWriteErr; err != nil {
		t.Fatal(err)
	}
	if err := <-cReadErr; err != nil {
		t.Fatal(err)
	}
	if err := <-cWriteErr; err != nil {
		t.Fatal(err)
	}
}

func writeChunks(ctx context.Context, w io.Writer, b []byte, chunkSize int) error {
	if chunkSize <= 0 {
		chunkSize = 1024
	}
	for len(b) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		chunk := b
		if len(chunk) > chunkSize {
			chunk = b[:chunkSize]
		}
		n, err := w.Write(chunk)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
