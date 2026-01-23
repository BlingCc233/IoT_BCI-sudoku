package apis

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

type ClientConfig struct {
	Obfs     iotbci.ObfsOptions
	Security iotbci.SecurityOptions
	Identity iotbci.IdentityOptions

	Rand   io.Reader
	Logger *slog.Logger
}

type ServerConfig struct {
	Obfs     iotbci.ObfsOptions
	Security iotbci.SecurityOptions
	Identity iotbci.IdentityOptions

	Replay     *iotbci.ReplayCache
	Revocation *iotbci.RevocationList

	Rand   io.Reader
	Logger *slog.Logger
}

func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Obfs: iotbci.ObfsOptions{
			ASCII:              "prefer_entropy",
			PaddingMin:         0,
			PaddingMax:         0,
			EnablePureDownlink: false,
		},
		Security: iotbci.SecurityOptions{
			HandshakeAEAD: iotbci.AEADChaCha20Poly1305,
			SessionAEAD:   iotbci.AEADChaCha20Poly1305,
		},
	}
}

func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Obfs: iotbci.ObfsOptions{
			ASCII:              "prefer_entropy",
			PaddingMin:         0,
			PaddingMax:         0,
			EnablePureDownlink: false,
		},
		Security: iotbci.SecurityOptions{
			HandshakeAEAD: iotbci.AEADChaCha20Poly1305,
			SessionAEAD:   iotbci.AEADChaCha20Poly1305,
		},
	}
}

func (c *ClientConfig) toOptions() *iotbci.ClientOptions {
	if c == nil {
		return nil
	}
	return &iotbci.ClientOptions{
		Obfs:     c.Obfs,
		Security: c.Security,
		Identity: c.Identity,
		Rand:     c.Rand,
		Logger:   c.Logger,
	}
}

func (c *ServerConfig) toOptions() *iotbci.ServerOptions {
	if c == nil {
		return nil
	}
	return &iotbci.ServerOptions{
		Obfs:       c.Obfs,
		Security:   c.Security,
		Identity:   c.Identity,
		Replay:     c.Replay,
		Revocation: c.Revocation,
		Rand:       c.Rand,
		Logger:     c.Logger,
	}
}

func ParseEd25519PublicKeyHex(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key length: %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

func ParseEd25519PrivateKeyHex(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("private key length must be 32(seed) or 64(priv), got %d", len(b))
	}
}

func ParseCertHexOrBase64(s string) (*iotbci.Cert, error) {
	raw, err := decodeHexOrBase64(s)
	if err != nil {
		return nil, err
	}
	return iotbci.ParseCert(raw)
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
