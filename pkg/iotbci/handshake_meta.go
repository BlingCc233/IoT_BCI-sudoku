package iotbci

// HandshakeMeta carries per-session identity hints for accounting and debugging.
type HandshakeMeta struct {
	// UserHash is a hex-encoded 8-byte value derived from the peer's private key seed:
	// Trunc8(SHA-256(seed)).
	UserHash string

	PeerSubject string
	PeerSerial  uint64
}
