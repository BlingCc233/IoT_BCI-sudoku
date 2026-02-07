package apis

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func TestClientConfigValidate(t *testing.T) {
	t.Parallel()

	masterPub, localPriv, cert := mustTestIdentity(t)

	makeValid := func() *ClientConfig {
		cfg := DefaultClientConfig()
		cfg.Security.PSK = "test-psk"
		cfg.Identity.MasterPublicKey = masterPub
		cfg.Identity.LocalPrivateKey = localPriv
		cfg.Identity.LocalCert = cert
		return cfg
	}

	tests := []struct {
		name    string
		mutate  func(cfg *ClientConfig)
		wantErr bool
	}{
		{
			name:    "valid",
			wantErr: false,
		},
		{
			name: "missing_obfs_key_and_psk",
			mutate: func(cfg *ClientConfig) {
				cfg.Security.PSK = ""
				cfg.Obfs.Key = ""
			},
			wantErr: true,
		},
		{
			name: "invalid_ascii_mode",
			mutate: func(cfg *ClientConfig) {
				cfg.Obfs.ASCII = "bad-mode"
			},
			wantErr: true,
		},
		{
			name: "invalid_padding_range",
			mutate: func(cfg *ClientConfig) {
				cfg.Obfs.PaddingMin = 80
				cfg.Obfs.PaddingMax = 20
			},
			wantErr: true,
		},
		{
			name: "invalid_custom_pattern",
			mutate: func(cfg *ClientConfig) {
				cfg.Obfs.CustomTables = []string{"xxxxppvv"}
			},
			wantErr: true,
		},
		{
			name: "missing_trust_anchor",
			mutate: func(cfg *ClientConfig) {
				cfg.Identity.MasterPublicKey = nil
				cfg.Identity.PeerPublicKey = nil
			},
			wantErr: true,
		},
		{
			name: "key_cert_mismatch",
			mutate: func(cfg *ClientConfig) {
				_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate key: %v", err)
				}
				cfg.Identity.LocalPrivateKey = otherPriv
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := makeValid()
			if tc.mutate != nil {
				tc.mutate(cfg)
			}
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestServerConfigValidate(t *testing.T) {
	t.Parallel()
	if err := (*ServerConfig)(nil).Validate(); err == nil {
		t.Fatalf("expected nil server config error")
	}

	masterPub, localPriv, cert := mustTestIdentity(t)
	cfg := DefaultServerConfig()
	cfg.Security.PSK = "test-psk"
	cfg.Identity.MasterPublicKey = masterPub
	cfg.Identity.LocalPrivateKey = localPriv
	cfg.Identity.LocalCert = cert
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustTestIdentity(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, *iotbci.Cert) {
	t.Helper()
	masterPub, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	localPub, localPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate local key: %v", err)
	}
	now := time.Now()
	cert, err := iotbci.IssueCert(masterPriv, "test-device", localPub, now.Add(-time.Hour), now.Add(time.Hour), 1)
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	return masterPub, localPriv, cert
}
