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
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/obfs/sudoku"
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

func (c *ClientConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("nil client config")
	}
	return validateCommon(c.Obfs, c.Security, c.Identity)
}

func (c *ServerConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("nil server config")
	}
	return validateCommon(c.Obfs, c.Security, c.Identity)
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

func validateCommon(obfs iotbci.ObfsOptions, sec iotbci.SecurityOptions, id iotbci.IdentityOptions) error {
	switch strings.TrimSpace(strings.ToLower(obfs.ASCII)) {
	case "", "entropy", "prefer_entropy", "ascii", "prefer_ascii":
	default:
		return fmt.Errorf("invalid obfs ASCII mode: %q", obfs.ASCII)
	}

	if obfs.PaddingMin < 0 || obfs.PaddingMin > 100 || obfs.PaddingMax < 0 || obfs.PaddingMax > 100 {
		return fmt.Errorf("padding range must be in [0,100], got min=%d max=%d", obfs.PaddingMin, obfs.PaddingMax)
	}
	if obfs.PaddingMin > obfs.PaddingMax {
		return fmt.Errorf("padding min greater than max: %d>%d", obfs.PaddingMin, obfs.PaddingMax)
	}

	if !isValidAEAD(sec.HandshakeAEAD) {
		return fmt.Errorf("invalid handshake AEAD: %q", sec.HandshakeAEAD)
	}
	if !isValidAEAD(sec.SessionAEAD) {
		return fmt.Errorf("invalid session AEAD: %q", sec.SessionAEAD)
	}

	psk := strings.TrimSpace(sec.PSK)
	obfsKey := strings.TrimSpace(obfs.Key)
	if obfsKey == "" {
		obfsKey = psk
	}
	if obfsKey == "" {
		return fmt.Errorf("missing obfs key/psk")
	}
	if sec.HandshakeAEAD != iotbci.AEADNone && psk == "" {
		return fmt.Errorf("handshake AEAD requires PSK")
	}

	if id.LocalCert == nil {
		return fmt.Errorf("missing local cert")
	}
	if len(id.LocalPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid local private key size: %d", len(id.LocalPrivateKey))
	}
	pub := id.LocalPrivateKey.Public().(ed25519.PublicKey)
	if len(id.LocalCert.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid local cert public key size: %d", len(id.LocalCert.PublicKey))
	}
	if !bytesEqual(pub, id.LocalCert.PublicKey) {
		return fmt.Errorf("private key does not match local cert")
	}
	if len(id.MasterPublicKey) == 0 && len(id.PeerPublicKey) == 0 {
		return fmt.Errorf("missing trust anchor: master public key or peer public key pin")
	}
	if len(id.MasterPublicKey) != 0 && len(id.MasterPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid master public key size: %d", len(id.MasterPublicKey))
	}
	if len(id.PeerPublicKey) != 0 && len(id.PeerPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid peer public key size: %d", len(id.PeerPublicKey))
	}

	if _, err := sudoku.NewTableSet(obfsKey, obfs.ASCII, obfs.CustomTables); err != nil {
		return fmt.Errorf("invalid obfs table config: %w", err)
	}
	return nil
}

func isValidAEAD(m iotbci.AEADMethod) bool {
	switch m {
	case "", iotbci.AEADNone, iotbci.AEADAES128GCM, iotbci.AEADChaCha20Poly1305:
		return true
	default:
		return false
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var x byte
	for i := range a {
		x |= a[i] ^ b[i]
	}
	return x == 0
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
