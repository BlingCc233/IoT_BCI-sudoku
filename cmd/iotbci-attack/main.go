package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

type attackReport struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Scenarios   []attackResult `json:"scenarios"`
}

type attackResult struct {
	Name        string   `json:"name"`
	Expected    string   `json:"expected"`
	Success     bool     `json:"success"`
	DurationMs  float64  `json:"duration_ms"`
	ServerError string   `json:"server_error,omitempty"`
	ClientError string   `json:"client_error,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

func main() {
	var (
		outPath = flag.String("out", "", "output JSON path (default: stdout)")
		timeout = flag.Duration("timeout", 10*time.Second, "overall timeout")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rep := attackReport{
		GeneratedAt: time.Now(),
		Scenarios: []attackResult{
			runReplay(ctx),
			runMITMTamper(ctx),
			runProbeFlood(ctx),
		},
	}

	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fatal(err)
	}
	if *outPath == "" {
		_, _ = os.Stdout.Write(append(b, '\n'))
		return
	}
	if err := os.WriteFile(*outPath, append(b, '\n'), 0o644); err != nil {
		fatal(err)
	}
}

func runReplay(ctx context.Context) attackResult {
	start := time.Now()
	res := attackResult{
		Name:     "replay",
		Expected: "server rejects replayed client handshake with ErrReplayDetected",
	}

	serverOpts, clientOpts, err := buildOpts(true)
	if err != nil {
		res.ClientError = err.Error()
		res.DurationMs = float64(time.Since(start)) / float64(time.Millisecond)
		return res
	}

	// First handshake: record client->server bytes.
	s1, c1 := net.Pipe()
	defer s1.Close()
	defer c1.Close()

	tap := &tapConn{Conn: c1}

	serverErr1 := make(chan error, 1)
	go func() {
		conn, _, err := iotbci.ServerHandshake(ctx, s1, serverOpts)
		if conn != nil {
			_ = conn.Close()
		}
		serverErr1 <- err
	}()

	conn1, _, cErr := iotbci.ClientHandshake(ctx, tap, clientOpts)
	if conn1 != nil {
		_ = conn1.Close()
	}
	sErr := <-serverErr1
	if cErr != nil || sErr != nil {
		if cErr != nil {
			res.ClientError = cErr.Error()
		}
		if sErr != nil {
			res.ServerError = sErr.Error()
		}
		res.DurationMs = float64(time.Since(start)) / float64(time.Millisecond)
		return res
	}

	recorded := tap.Bytes()
	if len(recorded) == 0 {
		res.ServerError = "no bytes captured from client"
		res.DurationMs = float64(time.Since(start)) / float64(time.Millisecond)
		return res
	}

	// Second handshake: replay the captured bytes.
	s2, c2 := net.Pipe()
	defer s2.Close()
	defer c2.Close()

	serverErr2 := make(chan error, 1)
	go func() {
		conn, _, err := iotbci.ServerHandshake(ctx, s2, serverOpts)
		if conn != nil {
			_ = conn.Close()
		}
		serverErr2 <- err
	}()

	go func() {
		_, _ = io.Copy(c2, bytes.NewReader(recorded))
		_ = c2.Close()
	}()

	err2 := <-serverErr2
	res.DurationMs = float64(time.Since(start)) / float64(time.Millisecond)
	if err2 == nil {
		res.ServerError = "expected replay rejection, got nil"
		return res
	}
	res.ServerError = err2.Error()
	res.Success = errors.Is(err2, iotbci.ErrReplayDetected)
	if !res.Success {
		res.Notes = append(res.Notes, "expected errors.Is(err, ErrReplayDetected)=true")
	}
	return res
}

func runMITMTamper(ctx context.Context) attackResult {
	start := time.Now()
	res := attackResult{
		Name:     "mitm-tamper",
		Expected: "server detects tampering during handshake (SuspiciousError/AuthFailed/ProtocolViolation)",
	}

	serverOpts, clientOpts, err := buildOpts(true)
	if err != nil {
		res.ClientError = err.Error()
		res.DurationMs = float64(time.Since(start)) / float64(time.Millisecond)
		return res
	}

	s, c := net.Pipe()
	defer s.Close()
	defer c.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, _, err := iotbci.ServerHandshake(ctx, s, serverOpts)
		if conn != nil {
			_ = conn.Close()
		}
		serverErr <- err
	}()

	tampered := &tamperConn{Conn: c}
	conn, _, cErr := iotbci.ClientHandshake(ctx, tampered, clientOpts)
	if conn != nil {
		_ = conn.Close()
	}
	sErr := <-serverErr

	res.DurationMs = float64(time.Since(start)) / float64(time.Millisecond)
	if cErr != nil {
		res.ClientError = cErr.Error()
	}
	if sErr != nil {
		res.ServerError = sErr.Error()
	}
	if sErr == nil {
		res.ServerError = "expected server handshake failure, got nil"
		return res
	}

	var suspicious *iotbci.SuspiciousError
	res.Success = errors.As(sErr, &suspicious) ||
		errors.Is(sErr, iotbci.ErrAuthFailed) ||
		errors.Is(sErr, iotbci.ErrProtocolViolation)
	if !res.Success {
		res.Notes = append(res.Notes, "unexpected server error type")
	}
	return res
}

func runProbeFlood(ctx context.Context) attackResult {
	start := time.Now()
	res := attackResult{
		Name:     "resource-probe-flood",
		Expected: "server rejects oversized handshake probe (bounded by maxProbeBytes)",
	}

	serverOpts, _, err := buildOpts(true)
	if err != nil {
		res.ServerError = err.Error()
		res.DurationMs = float64(time.Since(start)) / float64(time.Millisecond)
		return res
	}
	serverOpts.Security.MaxHandshakeSize = 8 * 1024

	s, c := net.Pipe()
	defer s.Close()
	defer c.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, _, err := iotbci.ServerHandshake(ctx, s, serverOpts)
		if conn != nil {
			_ = conn.Close()
		}
		serverErr <- err
	}()

	go func() {
		junk := make([]byte, 80*1024)
		for i := range junk {
			junk[i] = byte(i)
		}
		_, _ = c.Write(junk)
		_ = c.Close()
	}()

	err = <-serverErr
	res.DurationMs = float64(time.Since(start)) / float64(time.Millisecond)
	if err == nil {
		res.ServerError = "expected server rejection, got nil"
		return res
	}
	res.ServerError = err.Error()

	var suspicious *iotbci.SuspiciousError
	res.Success = errors.As(err, &suspicious)
	if !res.Success {
		res.Notes = append(res.Notes, "expected SuspiciousError for invalid probe")
	}
	return res
}

type tapConn struct {
	net.Conn
	buf bytes.Buffer
}

func (t *tapConn) Write(p []byte) (int, error) {
	n, err := t.Conn.Write(p)
	if n > 0 {
		_, _ = t.buf.Write(p[:n])
	}
	return n, err
}

func (t *tapConn) Bytes() []byte {
	if t == nil {
		return nil
	}
	b := t.buf.Bytes()
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

type tamperConn struct {
	net.Conn
	flipped bool
}

func (t *tamperConn) Write(p []byte) (int, error) {
	if t == nil {
		return 0, io.ErrClosedPipe
	}
	if !t.flipped && len(p) > 0 {
		cp := make([]byte, len(p))
		copy(cp, p)
		cp[0] ^= 0x01
		t.flipped = true
		return t.Conn.Write(cp)
	}
	return t.Conn.Write(p)
}

func buildOpts(enablePureDownlink bool) (*iotbci.ServerOptions, *iotbci.ClientOptions, error) {
	// Identity & certs (master-signed).
	masterPub, masterPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	serverCert, err := iotbci.IssueCert(masterPriv, "server-1", serverPub, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	if err != nil {
		return nil, nil, err
	}
	clientCert, err := iotbci.IssueCert(masterPriv, "device-1", clientPub, now.Add(-time.Hour), now.Add(24*time.Hour), 2)
	if err != nil {
		return nil, nil, err
	}

	sum := sha256.Sum256([]byte("iotbci-attack:" + now.Format(time.RFC3339Nano)))
	psk := "attack-psk:" + hex8(sum[:])

	serverOpts := &iotbci.ServerOptions{
		Obfs: iotbci.ObfsOptions{
			ASCII:              "prefer_entropy",
			CustomTables:       []string{"xppppxvv", "vppxppvx"},
			PaddingMin:         2,
			PaddingMax:         7,
			EnablePureDownlink: enablePureDownlink,
		},
		Security: iotbci.SecurityOptions{
			PSK:              psk,
			HandshakeAEAD:    iotbci.AEADChaCha20Poly1305,
			SessionAEAD:      iotbci.AEADChaCha20Poly1305,
			HandshakeTimeout: 2 * time.Second,
			TimeSkew:         2 * time.Minute,
			MaxHandshakeSize: 8 * 1024,
			ReplayWindow:     5 * time.Minute,
			ReplayCacheSize:  1024,
		},
		Identity: iotbci.IdentityOptions{
			MasterPublicKey: masterPub,
			LocalCert:       serverCert,
			LocalPrivateKey: serverPriv,
		},
		Replay: iotbci.NewReplayCache(1024, 5*time.Minute),
	}

	clientOpts := &iotbci.ClientOptions{
		Obfs: iotbci.ObfsOptions{
			ASCII:              "prefer_entropy",
			CustomTables:       []string{"xppppxvv", "vppxppvx"},
			PaddingMin:         2,
			PaddingMax:         7,
			EnablePureDownlink: enablePureDownlink,
		},
		Security: iotbci.SecurityOptions{
			PSK:              psk,
			HandshakeAEAD:    iotbci.AEADChaCha20Poly1305,
			SessionAEAD:      iotbci.AEADChaCha20Poly1305,
			HandshakeTimeout: 2 * time.Second,
			TimeSkew:         2 * time.Minute,
			MaxHandshakeSize: 8 * 1024,
		},
		Identity: iotbci.IdentityOptions{
			MasterPublicKey: masterPub,
			LocalCert:       clientCert,
			LocalPrivateKey: clientPriv,
		},
	}

	return serverOpts, clientOpts, nil
}

func hex8(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	var out [16]byte
	const hex = "0123456789abcdef"
	for i := 0; i < 8; i++ {
		out[i*2] = hex[b[i]>>4]
		out[i*2+1] = hex[b[i]&0x0F]
	}
	return string(out[:])
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
