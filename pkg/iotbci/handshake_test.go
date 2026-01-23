package iotbci

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type repeatReader struct {
	b byte
}

func (r repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

func issueTestCert(t *testing.T, issuerPriv ed25519.PrivateKey, subject string, subjectPub ed25519.PublicKey, serial uint64) *Cert {
	t.Helper()
	now := time.Now()
	c, err := IssueCert(issuerPriv, subject, subjectPub, now.Add(-time.Hour), now.Add(24*time.Hour), serial)
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	return c
}

func TestHandshakeRoundTrip_PureDownlink(t *testing.T) {
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	serverCert := issueTestCert(t, masterPriv, "server-1", serverPub, 1)
	clientCert := issueTestCert(t, masterPriv, "device-1", clientPub, 2)

	psk := "test-psk-1"

	serverOpts := &ServerOptions{
		Obfs: ObfsOptions{
			ASCII:              "prefer_entropy",
			CustomTables:       []string{"xppppxvv", "vppxppvx"},
			PaddingMin:         0,
			PaddingMax:         0,
			EnablePureDownlink: true,
		},
		Security: SecurityOptions{
			PSK:              psk,
			HandshakeAEAD:    AEADChaCha20Poly1305,
			SessionAEAD:      AEADChaCha20Poly1305,
			HandshakeTimeout: 2 * time.Second,
			TimeSkew:         2 * time.Minute,
			MaxHandshakeSize: 8 * 1024,
			ReplayWindow:     5 * time.Minute,
			ReplayCacheSize:  128,
		},
		Identity: IdentityOptions{
			MasterPublicKey: masterPub,
			LocalCert:       serverCert,
			LocalPrivateKey: serverPriv,
		},
	}
	clientOpts := &ClientOptions{
		Obfs: ObfsOptions{
			ASCII:              "prefer_entropy",
			CustomTables:       []string{"xppppxvv", "vppxppvx"},
			PaddingMin:         0,
			PaddingMax:         0,
			EnablePureDownlink: true,
		},
		Security: SecurityOptions{
			PSK:              psk,
			HandshakeAEAD:    AEADChaCha20Poly1305,
			SessionAEAD:      AEADChaCha20Poly1305,
			HandshakeTimeout: 2 * time.Second,
			TimeSkew:         2 * time.Minute,
			MaxHandshakeSize: 8 * 1024,
		},
		Identity: IdentityOptions{
			MasterPublicKey: masterPub,
			LocalCert:       clientCert,
			LocalPrivateKey: clientPriv,
		},
	}

	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	serverDone := make(chan struct{})
	var sConn net.Conn
	var sMeta *HandshakeMeta
	var sErr error
	go func() {
		defer close(serverDone)
		sConn, sMeta, sErr = ServerHandshake(context.Background(), sRaw, serverOpts)
	}()

	cConn, _, cErr := ClientHandshake(context.Background(), cRaw, clientOpts)
	if cErr != nil {
		t.Fatalf("client handshake: %v", cErr)
	}
	defer cConn.Close()

	<-serverDone
	if sErr != nil {
		t.Fatalf("server handshake: %v", sErr)
	}
	defer sConn.Close()

	if sMeta == nil || sMeta.PeerSubject != "device-1" {
		t.Fatalf("unexpected server meta: %#v", sMeta)
	}

	// Client -> Server
	msg := []byte("hello-bci")
	go func() {
		_, _ = cConn.Write(msg)
	}()
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(sConn, buf); err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("payload mismatch")
	}
}

func TestHandshakeReplayDetected(t *testing.T) {
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	serverCert := issueTestCert(t, masterPriv, "server-1", serverPub, 1)
	clientCert := issueTestCert(t, masterPriv, "device-1", clientPub, 2)

	psk := "test-psk-2"
	replay := NewReplayCache(32, 5*time.Minute)

	serverOpts := &ServerOptions{
		Obfs: ObfsOptions{
			ASCII:              "prefer_entropy",
			CustomTables:       []string{"xppppxvv"},
			PaddingMin:         0,
			PaddingMax:         0,
			EnablePureDownlink: true,
		},
		Security: SecurityOptions{
			PSK:              psk,
			HandshakeAEAD:    AEADChaCha20Poly1305,
			SessionAEAD:      AEADChaCha20Poly1305,
			HandshakeTimeout: 2 * time.Second,
			TimeSkew:         2 * time.Minute,
			MaxHandshakeSize: 8 * 1024,
			ReplayWindow:     5 * time.Minute,
			ReplayCacheSize:  32,
		},
		Identity: IdentityOptions{
			MasterPublicKey: masterPub,
			LocalCert:       serverCert,
			LocalPrivateKey: serverPriv,
		},
		Replay: replay,
	}

	clientOpts := func() *ClientOptions {
		return &ClientOptions{
			Obfs: ObfsOptions{
				ASCII:              "prefer_entropy",
				CustomTables:       []string{"xppppxvv"},
				PaddingMin:         0,
				PaddingMax:         0,
				EnablePureDownlink: true,
			},
			Security: SecurityOptions{
				PSK:              psk,
				HandshakeAEAD:    AEADChaCha20Poly1305,
				SessionAEAD:      AEADChaCha20Poly1305,
				HandshakeTimeout: 2 * time.Second,
				TimeSkew:         2 * time.Minute,
				MaxHandshakeSize: 8 * 1024,
			},
			Identity: IdentityOptions{
				MasterPublicKey: masterPub,
				LocalCert:       clientCert,
				LocalPrivateKey: clientPriv,
			},
			Rand: repeatReader{b: 0x42},
		}
	}

	// 1st handshake should pass.
	{
		sRaw, cRaw := net.Pipe()
		serverDone := make(chan struct{})
		var sErr error
		go func() {
			defer close(serverDone)
			_, _, sErr = ServerHandshake(context.Background(), sRaw, serverOpts)
		}()
		_, _, cErr := ClientHandshake(context.Background(), cRaw, clientOpts())
		if cErr != nil {
			t.Fatalf("client handshake(1): %v", cErr)
		}
		<-serverDone
		if sErr != nil {
			t.Fatalf("server handshake(1): %v", sErr)
		}
	}

	// 2nd handshake with same nonce should be rejected as replay.
	{
		sRaw, cRaw := net.Pipe()
		serverDone := make(chan struct{})
		var sErr error
		go func() {
			defer close(serverDone)
			_, _, sErr = ServerHandshake(context.Background(), sRaw, serverOpts)
		}()
		_, _, cErr := ClientHandshake(context.Background(), cRaw, clientOpts())
		if cErr != nil {
			// Client will fail because server aborts; both acceptable.
		}
		<-serverDone
		if sErr == nil || !errors.Is(sErr, ErrReplayDetected) {
			t.Fatalf("expected replay error, got %v", sErr)
		}
	}
}
