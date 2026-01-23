// Package apis exposes a stable, high-level Go API for the IoT_BCI-sudoku protocol.
//
// The core protocol implementation lives in pkg/iotbci. This package provides
// convenience wrappers for:
//   - Dialing and accepting authenticated sessions (Ed25519 + anti-replay handshake)
//   - Using optional mux and UoT layers
//   - Parsing keys/certs from common encodings (hex / base64)
//
// HTTP masking is intentionally not included in this repository.
package apis
