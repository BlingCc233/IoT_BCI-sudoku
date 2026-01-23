package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func TestServe_Errors(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := Serve(ctx, nil); err == nil {
		t.Fatalf("expected error for nil config")
	}
	if err := Serve(ctx, &Config{}); err == nil {
		t.Fatalf("expected error for missing listen")
	}
}

func TestDialAndRun_Errors(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := DialAndRun(ctx, nil); err == nil {
		t.Fatalf("expected error for nil config")
	}
	if err := DialAndRun(ctx, &Config{}); err == nil {
		t.Fatalf("expected error for missing server")
	}
}

func TestServeLoopAndDialAndRun_AllApps(t *testing.T) {
	t.Parallel()

	apps := []string{"stream", "mux", "uot"}
	for _, app := range apps {
		t.Run(app, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer ln.Close()

			masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
			serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
			clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

			now := time.Now()
			serverCert, err := iotbci.IssueCert(masterPriv, "server-1", serverPub, now.Add(-time.Hour), now.Add(time.Hour), 1)
			if err != nil {
				t.Fatal(err)
			}
			clientCert, err := iotbci.IssueCert(masterPriv, "device-1", clientPub, now.Add(-time.Hour), now.Add(time.Hour), 2)
			if err != nil {
				t.Fatal(err)
			}
			serverCertRaw, err := serverCert.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			clientCertRaw, err := clientCert.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			psk := "psk-1"
			obfs := ObfsConfig{
				ASCII:              "prefer_entropy",
				CustomTables:       []string{"xppppxvv", "vppxppvx"},
				PaddingMin:         0,
				PaddingMax:         2,
				EnablePureDownlink: false,
			}
			sec := SecurityConfig{
				PSK:                 psk,
				HandshakeAEAD:       "chacha20-poly1305",
				SessionAEAD:         "chacha20-poly1305",
				HandshakeTimeoutSec: 2,
				TimeSkewSec:         60,
				ReplayWindowSec:     60,
				ReplayCacheSize:     1024,
				MaxHandshakeSize:    8 * 1024,
			}

			serverCfg := &Config{
				Mode: "server",
				App:  app,
				Obfs: obfs,
				Security: SecurityConfig{
					PSK:                 sec.PSK,
					HandshakeAEAD:       sec.HandshakeAEAD,
					SessionAEAD:         sec.SessionAEAD,
					HandshakeTimeoutSec: sec.HandshakeTimeoutSec,
					TimeSkewSec:         sec.TimeSkewSec,
					ReplayWindowSec:     sec.ReplayWindowSec,
					ReplayCacheSize:     sec.ReplayCacheSize,
					MaxHandshakeSize:    sec.MaxHandshakeSize,
				},
				Identity: IdentityConfig{
					MasterPublicKeyHex: hex.EncodeToString(masterPub),
					LocalPrivateKeyHex: hex.EncodeToString(serverPriv),
					LocalCert:          base64.StdEncoding.EncodeToString(serverCertRaw),
				},
				SuspiciousAction: "fallback",
			}

			clientCfg := &Config{
				Mode:   "client",
				Server: ln.Addr().String(),
				App:    app,
				Obfs:   obfs,
				Security: SecurityConfig{
					PSK:                 sec.PSK,
					HandshakeAEAD:       sec.HandshakeAEAD,
					SessionAEAD:         sec.SessionAEAD,
					HandshakeTimeoutSec: sec.HandshakeTimeoutSec,
					TimeSkewSec:         sec.TimeSkewSec,
					MaxHandshakeSize:    sec.MaxHandshakeSize,
				},
				Identity: IdentityConfig{
					MasterPublicKeyHex: hex.EncodeToString(masterPub),
					LocalPrivateKeyHex: hex.EncodeToString(clientPriv),
					LocalCert:          base64.StdEncoding.EncodeToString(clientCertRaw),
				},
				BCI: BCISimConfig{
					Frames:            8,
					IntervalMillis:    0,
					DeterministicSeed: 1,
				},
			}

			// Ensure ToClientOptions is exercised (and valid).
			if _, err := clientCfg.ToClientOptions(); err != nil {
				t.Fatalf("ToClientOptions: %v", err)
			}

			opts, err := serverCfg.ToServerOptions()
			if err != nil {
				t.Fatalf("ToServerOptions: %v", err)
			}

			serverDone := make(chan error, 1)
			go func() {
				serverDone <- serveLoop(ctx, serverCfg, opts, ln)
			}()

			if err := DialAndRun(ctx, clientCfg); err != nil {
				t.Fatalf("DialAndRun: %v", err)
			}
			cancel()
			if err := <-serverDone; err != nil {
				t.Fatalf("server: %v", err)
			}
		})
	}
}
