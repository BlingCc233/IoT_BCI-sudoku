package iotbci

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"time"
)

type AEADMethod string

const (
	AEADNone              AEADMethod = "none"
	AEADAES128GCM         AEADMethod = "aes-128-gcm"
	AEADChaCha20Poly1305  AEADMethod = "chacha20-poly1305"
	defaultHandshakeMagic            = "IBC1"
)

type ObfsOptions struct {
	// Key is the Sudoku table seed. If empty, the security PSK is used.
	Key string

	// ASCII controls the appearance preference: "prefer_ascii" or "prefer_entropy".
	ASCII string

	// CustomTables enables per-session table rotation. Each entry is an 8-symbol pattern
	// with exactly 2 x, 4 p, 2 v (semantic-corrected).
	CustomTables []string

	// PaddingMin/PaddingMax are in percent (0..100). The per-connection padding rate is
	// uniformly sampled from [min,max].
	PaddingMin int
	PaddingMax int

	// EnablePureDownlink keeps downlink in pure Sudoku mode. If false, downlink uses
	// 6-bit packing for better bandwidth utilization (AEAD recommended).
	EnablePureDownlink bool

	// EnablePackedUplink enables 6-bit packing on the uplink (client->server).
	//
	// When combined with EnablePureDownlink=false, both directions use PackedConn
	// (maximum throughput / minimum CPU overhead).
	EnablePackedUplink bool
}

type SecurityOptions struct {
	// PSK is an optional pre-shared secret used to protect the handshake (active probing
	// resistance) and to seed the Sudoku table when Obfs.Key is empty.
	PSK string

	HandshakeAEAD AEADMethod
	SessionAEAD   AEADMethod

	HandshakeTimeout time.Duration
	TimeSkew         time.Duration

	ReplayWindow    time.Duration
	ReplayCacheSize int

	// MaxHandshakeSize caps a single handshake message body (bytes).
	MaxHandshakeSize int
}

type IdentityOptions struct {
	// MasterPublicKey is a trust anchor used to verify peer certificates. If nil, the
	// peer can be verified via PeerPublicKey pinning.
	MasterPublicKey ed25519.PublicKey

	// PeerPublicKey is an optional pin for deployments without a master CA.
	PeerPublicKey ed25519.PublicKey

	LocalCert       *Cert
	LocalPrivateKey ed25519.PrivateKey
}

type ClientOptions struct {
	Obfs     ObfsOptions
	Security SecurityOptions
	Identity IdentityOptions

	Rand   io.Reader
	Logger *slog.Logger
}

type ServerOptions struct {
	Obfs     ObfsOptions
	Security SecurityOptions
	Identity IdentityOptions

	Replay     *ReplayCache
	Revocation *RevocationList

	Rand   io.Reader
	Logger *slog.Logger
}

func (o *SecurityOptions) setDefaults() {
	if o.HandshakeAEAD == "" {
		o.HandshakeAEAD = AEADChaCha20Poly1305
	}
	if o.SessionAEAD == "" {
		o.SessionAEAD = AEADChaCha20Poly1305
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 5 * time.Second
	}
	if o.TimeSkew <= 0 {
		o.TimeSkew = 30 * time.Second
	}
	if o.ReplayWindow <= 0 {
		o.ReplayWindow = 2 * time.Minute
	}
	if o.ReplayCacheSize <= 0 {
		o.ReplayCacheSize = 4096
	}
	if o.MaxHandshakeSize <= 0 {
		o.MaxHandshakeSize = 16 * 1024
	}
}

func (o *ClientOptions) setDefaults() {
	o.Security.setDefaults()
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
}

func (o *ServerOptions) setDefaults() {
	o.Security.setDefaults()
	if o.Replay == nil {
		o.Replay = NewReplayCache(o.Security.ReplayCacheSize, o.Security.ReplayWindow)
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	if o.Revocation == nil {
		o.Revocation = &RevocationList{}
	}
}
