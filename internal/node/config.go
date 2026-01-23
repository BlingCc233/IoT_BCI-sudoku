package node

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

type Config struct {
	Mode string `json:"mode"` // "server" | "client"

	Listen string `json:"listen,omitempty"`
	Server string `json:"server,omitempty"`

	App string `json:"app"` // "stream" | "mux" | "uot"

	FallbackAddr     string `json:"fallback_addr,omitempty"`
	SuspiciousAction string `json:"suspicious_action,omitempty"` // "fallback" | "silent"

	Obfs     ObfsConfig     `json:"obfs"`
	Security SecurityConfig `json:"security"`
	Identity IdentityConfig `json:"identity"`

	BCI BCISimConfig `json:"bci"`
}

type ObfsConfig struct {
	Key                string   `json:"key,omitempty"`
	ASCII              string   `json:"ascii,omitempty"`
	CustomTables       []string `json:"custom_tables,omitempty"`
	PaddingMin         int      `json:"padding_min"`
	PaddingMax         int      `json:"padding_max"`
	EnablePureDownlink bool     `json:"enable_pure_downlink"`
}

type SecurityConfig struct {
	PSK                 string `json:"psk,omitempty"`
	HandshakeAEAD       string `json:"handshake_aead,omitempty"`
	SessionAEAD         string `json:"session_aead,omitempty"`
	HandshakeTimeoutSec int    `json:"handshake_timeout_sec,omitempty"`
	TimeSkewSec         int    `json:"time_skew_sec,omitempty"`
	ReplayWindowSec     int    `json:"replay_window_sec,omitempty"`
	ReplayCacheSize     int    `json:"replay_cache_size,omitempty"`
	MaxHandshakeSize    int    `json:"max_handshake_size,omitempty"`
}

type IdentityConfig struct {
	MasterPublicKeyHex string `json:"master_public_key_hex,omitempty"`
	PeerPublicKeyHex   string `json:"peer_public_key_hex,omitempty"`

	LocalPrivateKeyHex string `json:"local_private_key_hex,omitempty"` // 32-byte seed or 64-byte private key
	LocalCert          string `json:"local_cert,omitempty"`            // base64 or hex
}

type BCISimConfig struct {
	Channels          int   `json:"channels"`
	SampleRateHz      int   `json:"sample_rate_hz"`
	SamplesPerChannel int   `json:"samples_per_channel"`
	Frames            int   `json:"frames"`
	IntervalMillis    int   `json:"interval_ms"`
	DeterministicSeed int64 `json:"seed"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	cfg.App = strings.ToLower(strings.TrimSpace(cfg.App))
	cfg.SuspiciousAction = strings.ToLower(strings.TrimSpace(cfg.SuspiciousAction))
	if cfg.SuspiciousAction == "" {
		cfg.SuspiciousAction = "fallback"
	}
	return &cfg, nil
}

func (c *Config) ToServerOptions() (*iotbci.ServerOptions, error) {
	if c == nil {
		return nil, fmt.Errorf("nil config")
	}
	identity, err := c.parseIdentity()
	if err != nil {
		return nil, err
	}
	sec := iotbci.SecurityOptions{
		PSK:              c.Security.PSK,
		HandshakeAEAD:    iotbci.AEADMethod(strings.ToLower(strings.TrimSpace(c.Security.HandshakeAEAD))),
		SessionAEAD:      iotbci.AEADMethod(strings.ToLower(strings.TrimSpace(c.Security.SessionAEAD))),
		MaxHandshakeSize: c.Security.MaxHandshakeSize,
		ReplayCacheSize:  c.Security.ReplayCacheSize,
	}
	if c.Security.HandshakeTimeoutSec > 0 {
		sec.HandshakeTimeout = time.Duration(c.Security.HandshakeTimeoutSec) * time.Second
	}
	if c.Security.TimeSkewSec > 0 {
		sec.TimeSkew = time.Duration(c.Security.TimeSkewSec) * time.Second
	}
	if c.Security.ReplayWindowSec > 0 {
		sec.ReplayWindow = time.Duration(c.Security.ReplayWindowSec) * time.Second
	}

	return &iotbci.ServerOptions{
		Obfs: iotbci.ObfsOptions{
			Key:                c.Obfs.Key,
			ASCII:              c.Obfs.ASCII,
			CustomTables:       c.Obfs.CustomTables,
			PaddingMin:         c.Obfs.PaddingMin,
			PaddingMax:         c.Obfs.PaddingMax,
			EnablePureDownlink: c.Obfs.EnablePureDownlink,
		},
		Security: sec,
		Identity: identity,
	}, nil
}

func (c *Config) ToClientOptions() (*iotbci.ClientOptions, error) {
	if c == nil {
		return nil, fmt.Errorf("nil config")
	}
	identity, err := c.parseIdentity()
	if err != nil {
		return nil, err
	}
	sec := iotbci.SecurityOptions{
		PSK:              c.Security.PSK,
		HandshakeAEAD:    iotbci.AEADMethod(strings.ToLower(strings.TrimSpace(c.Security.HandshakeAEAD))),
		SessionAEAD:      iotbci.AEADMethod(strings.ToLower(strings.TrimSpace(c.Security.SessionAEAD))),
		MaxHandshakeSize: c.Security.MaxHandshakeSize,
	}
	if c.Security.HandshakeTimeoutSec > 0 {
		sec.HandshakeTimeout = time.Duration(c.Security.HandshakeTimeoutSec) * time.Second
	}
	if c.Security.TimeSkewSec > 0 {
		sec.TimeSkew = time.Duration(c.Security.TimeSkewSec) * time.Second
	}
	return &iotbci.ClientOptions{
		Obfs: iotbci.ObfsOptions{
			Key:                c.Obfs.Key,
			ASCII:              c.Obfs.ASCII,
			CustomTables:       c.Obfs.CustomTables,
			PaddingMin:         c.Obfs.PaddingMin,
			PaddingMax:         c.Obfs.PaddingMax,
			EnablePureDownlink: c.Obfs.EnablePureDownlink,
		},
		Security: sec,
		Identity: identity,
	}, nil
}

func (c *Config) parseIdentity() (iotbci.IdentityOptions, error) {
	var out iotbci.IdentityOptions

	if strings.TrimSpace(c.Identity.MasterPublicKeyHex) != "" {
		b, err := hex.DecodeString(strings.TrimSpace(c.Identity.MasterPublicKeyHex))
		if err != nil {
			return out, fmt.Errorf("master_public_key_hex: %w", err)
		}
		if len(b) != ed25519.PublicKeySize {
			return out, fmt.Errorf("master_public_key_hex length: %d", len(b))
		}
		out.MasterPublicKey = ed25519.PublicKey(b)
	}
	if strings.TrimSpace(c.Identity.PeerPublicKeyHex) != "" {
		b, err := hex.DecodeString(strings.TrimSpace(c.Identity.PeerPublicKeyHex))
		if err != nil {
			return out, fmt.Errorf("peer_public_key_hex: %w", err)
		}
		if len(b) != ed25519.PublicKeySize {
			return out, fmt.Errorf("peer_public_key_hex length: %d", len(b))
		}
		out.PeerPublicKey = ed25519.PublicKey(b)
	}

	privHex := strings.TrimSpace(c.Identity.LocalPrivateKeyHex)
	if privHex == "" {
		return out, fmt.Errorf("local_private_key_hex is required")
	}
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return out, fmt.Errorf("local_private_key_hex: %w", err)
	}
	switch len(privBytes) {
	case ed25519.SeedSize:
		out.LocalPrivateKey = ed25519.NewKeyFromSeed(privBytes)
	case ed25519.PrivateKeySize:
		out.LocalPrivateKey = ed25519.PrivateKey(privBytes)
	default:
		return out, fmt.Errorf("local_private_key_hex must be 32(seed) or 64(priv), got %d", len(privBytes))
	}

	certRawStr := strings.TrimSpace(c.Identity.LocalCert)
	if certRawStr == "" {
		return out, fmt.Errorf("local_cert is required")
	}
	certBytes, err := decodeHexOrBase64(certRawStr)
	if err != nil {
		return out, fmt.Errorf("local_cert: %w", err)
	}
	cert, err := iotbci.ParseCert(certBytes)
	if err != nil {
		return out, err
	}
	out.LocalCert = cert

	return out, nil
}

func decodeHexOrBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	isHex := true
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			isHex = false
			break
		}
	}
	if isHex && len(s)%2 == 0 {
		return hex.DecodeString(s)
	}
	return base64.StdEncoding.DecodeString(s)
}
