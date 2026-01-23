//go:build stress && !race

package iotbci

import (
	"context"
	"net"
	"runtime/debug"
	"testing"
	"time"
)

func TestStress_MemoryLimit_Smoke(t *testing.T) {
	old := debug.SetMemoryLimit(128 << 20) // 128 MiB
	t.Cleanup(func() { debug.SetMemoryLimit(old) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverOpts, clientOpts := newStressHandshakeOptions(t)
	serverOpts.setDefaults()
	clientOpts.setDefaults()

	// Run a smaller count under the memory limit.
	handshakes := 50
	for i := 0; i < handshakes; i++ {
		sRaw, cRaw := net.Pipe()

		errCh := make(chan error, 1)
		go func() {
			defer sRaw.Close()
			conn, _, err := ServerHandshake(ctx, sRaw, serverOpts)
			if err != nil {
				errCh <- err
				return
			}
			_ = conn.Close()
			errCh <- nil
		}()

		conn, _, err := ClientHandshake(ctx, cRaw, clientOpts)
		_ = cRaw.Close()
		if err != nil {
			t.Fatalf("handshake: %v", err)
		}
		_ = conn.Close()

		if err := <-errCh; err != nil {
			t.Fatalf("server handshake: %v", err)
		}
	}
}
