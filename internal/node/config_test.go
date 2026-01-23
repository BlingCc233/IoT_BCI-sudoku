package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func TestLoadAndToOptions(t *testing.T) {
	t.Parallel()

	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now()
	serverCert, err := iotbci.IssueCert(masterPriv, "server-1", serverPub, now.Add(-time.Hour), now.Add(time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := serverCert.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	cfgJSON := `{
  "mode": "server",
  "listen": "127.0.0.1:0",
  "app": "stream",
  "obfs": {
    "ascii": "prefer_entropy",
    "custom_tables": ["xppppxvv"],
    "padding_min": 1,
    "padding_max": 2,
    "enable_pure_downlink": false
  },
  "security": {
    "psk": "psk-1",
    "handshake_aead": "chacha20-poly1305",
    "session_aead": "chacha20-poly1305",
    "handshake_timeout_sec": 3,
    "time_skew_sec": 5,
    "replay_window_sec": 7,
    "replay_cache_size": 99,
    "max_handshake_size": 4096
  },
  "identity": {
    "master_public_key_hex": "` + hex.EncodeToString(masterPub) + `",
    "local_private_key_hex": "` + hex.EncodeToString(serverPriv) + `",
    "local_cert": "` + base64.StdEncoding.EncodeToString(certBytes) + `"
  }
}`

	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(path, []byte(cfgJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "server" || cfg.App != "stream" {
		t.Fatalf("unexpected mode/app: %q/%q", cfg.Mode, cfg.App)
	}

	opts, err := cfg.ToServerOptions()
	if err != nil {
		t.Fatal(err)
	}
	if opts.Security.PSK != "psk-1" {
		t.Fatalf("psk mismatch")
	}
	if opts.Security.MaxHandshakeSize != 4096 {
		t.Fatalf("max handshake size mismatch")
	}
	if opts.Identity.LocalCert == nil || opts.Identity.LocalCert.Subject != "server-1" {
		t.Fatalf("cert mismatch")
	}
}
