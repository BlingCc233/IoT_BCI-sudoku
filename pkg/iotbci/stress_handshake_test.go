//go:build stress

package iotbci

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestStress_HandshakeParallel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	serverOpts, clientOpts := newStressHandshakeOptions(t)
	serverOpts.setDefaults()
	clientOpts.setDefaults()

	handshakes := stressEnvInt("IOTBCI_STRESS_HANDSHAKES", 200)
	concurrency := stressEnvInt("IOTBCI_STRESS_CONCURRENCY", runtime.GOMAXPROCS(0)*2)
	if concurrency < 1 {
		concurrency = 1
	}

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	errCh := make(chan error, handshakes)
	for i := 0; i < handshakes; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()

			hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
			defer hcancel()

			sRaw, cRaw := net.Pipe()
			defer sRaw.Close()
			defer cRaw.Close()

			serverErr := make(chan error, 1)
			go func() {
				conn, _, err := ServerHandshake(hctx, sRaw, serverOpts)
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()

				buf := make([]byte, 32)
				if _, err := io.ReadFull(conn, buf); err != nil {
					serverErr <- err
					return
				}
				if _, err := conn.Write(buf); err != nil {
					serverErr <- err
					return
				}
				serverErr <- nil
			}()

			conn, _, err := ClientHandshake(hctx, cRaw, clientOpts)
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()

			msg := make([]byte, 32)
			msg[0] = byte(i)
			msg[1] = byte(i >> 8)
			msg[2] = byte(i >> 16)
			msg[3] = byte(i >> 24)

			if _, err := conn.Write(msg); err != nil {
				errCh <- err
				return
			}
			resp := make([]byte, 32)
			if _, err := io.ReadFull(conn, resp); err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(resp, msg) {
				errCh <- fmt.Errorf("echo mismatch")
				return
			}

			if err := <-serverErr; err != nil {
				errCh <- err
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("stress handshake failed: %v", err)
		}
	}
}

func TestStress_ReplayCacheConcurrent(t *testing.T) {
	c := NewReplayCache(1024, 2*time.Minute)
	now := time.Unix(100, 0)
	token := []byte("same-token")

	n := stressEnvInt("IOTBCI_STRESS_REPLAY_CALLS", 512)
	var wg sync.WaitGroup
	results := make(chan bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- c.SeenOrAdd(token, now)
		}()
	}
	wg.Wait()
	close(results)

	var falseCount int
	for seen := range results {
		if !seen {
			falseCount++
		}
	}
	if falseCount != 1 {
		t.Fatalf("expected exactly 1 add (false), got %d", falseCount)
	}
}

func newStressHandshakeOptions(t *testing.T) (*ServerOptions, *ClientOptions) {
	t.Helper()

	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now()
	serverCert, err := IssueCert(masterPriv, "server", serverPub, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := IssueCert(masterPriv, "device", clientPub, now.Add(-time.Hour), now.Add(24*time.Hour), 2)
	if err != nil {
		t.Fatal(err)
	}

	obfs := ObfsOptions{
		ASCII:        "prefer_entropy",
		CustomTables: []string{"xppppxvv", "vppxppvx"},
		PaddingMin:   0,
		PaddingMax:   3,
	}
	sec := SecurityOptions{
		PSK:              "stress-psk",
		HandshakeAEAD:    AEADChaCha20Poly1305,
		SessionAEAD:      AEADChaCha20Poly1305,
		HandshakeTimeout: 5 * time.Second,
		TimeSkew:         2 * time.Minute,
		ReplayWindow:     5 * time.Minute,
		ReplayCacheSize:  8192,
		MaxHandshakeSize: 8 * 1024,
	}

	s := &ServerOptions{
		Obfs:     obfs,
		Security: sec,
		Identity: IdentityOptions{
			MasterPublicKey: masterPub,
			LocalCert:       serverCert,
			LocalPrivateKey: serverPriv,
		},
	}
	c := &ClientOptions{
		Obfs:     obfs,
		Security: sec,
		Identity: IdentityOptions{
			MasterPublicKey: masterPub,
			LocalCert:       clientCert,
			LocalPrivateKey: clientPriv,
		},
	}
	return s, c
}

func stressEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
