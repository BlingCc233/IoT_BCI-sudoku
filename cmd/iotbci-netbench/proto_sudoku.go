package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net"
	"runtime/debug"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func runSudokuServer(ctx context.Context, listen string, cfg bench.RunConfig, opts commonOpts, pure bool) (bench.ProtocolResult, string, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}

	masterPub, serverCert, serverPriv, clientCert, _, err := netbenchIdentityBundle()
	if err != nil {
		return bench.ProtocolResult{}, "", err
	}
	serverOpts := buildSudokuServerOptions(masterPub, serverCert, serverPriv, opts, pure)
	_ = clientCert

	stats := &bench.WireStats{}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return bench.ProtocolResult{}, "", err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	raw, err := ln.Accept()
	if err != nil {
		return bench.ProtocolResult{}, ln.Addr().String(), err
	}
	defer raw.Close()

	counted := bench.WrapConn(raw, stats)
	sConn, _, err := iotbci.ServerHandshake(ctx, counted, serverOpts)
	if err != nil {
		return bench.ProtocolResult{}, ln.Addr().String(), err
	}
	defer sConn.Close()

	oldGC := debug.SetGCPercent(200)
	defer debug.SetGCPercent(oldGC)
	mem, memBase := startMemPhaseSampler(5 * time.Millisecond)
	start := time.Now()

	buf := make([]byte, cfg.PayloadSize)
	for i := 0; i < cfg.Messages; i++ {
		_ = raw.SetReadDeadline(time.Now().Add(20 * time.Second))
		if err := readFull(sConn, buf); err != nil {
			return bench.ProtocolResult{}, ln.Addr().String(), err
		}
		_ = raw.SetWriteDeadline(time.Now().Add(20 * time.Second))
		if err := writeFull(sConn, buf); err != nil {
			return bench.ProtocolResult{}, ln.Addr().String(), err
		}
	}
	_ = raw.SetDeadline(time.Time{})

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats(sudokuProtoName(pure), cfg, dur, peak, peakDelta, stats, nil), ln.Addr().String(), nil
}

func runSudokuClient(ctx context.Context, server string, cfg bench.RunConfig, opts commonOpts, pure bool) (bench.ProtocolResult, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}

	masterPub, _, _, clientCert, clientPriv, err := netbenchIdentityBundle()
	if err != nil {
		return bench.ProtocolResult{}, err
	}
	clientOpts := buildSudokuClientOptions(masterPub, clientCert, clientPriv, opts, pure)

	stats := &bench.WireStats{}
	raw, err := net.DialTimeout("tcp", server, 8*time.Second)
	if err != nil {
		return bench.ProtocolResult{}, err
	}
	defer raw.Close()
	counted := bench.WrapConn(raw, stats)

	cConn, _, err := iotbci.ClientHandshake(ctx, counted, clientOpts)
	if err != nil {
		return bench.ProtocolResult{}, err
	}
	defer cConn.Close()

	oldGC := debug.SetGCPercent(200)
	defer debug.SetGCPercent(oldGC)
	mem, memBase := startMemPhaseSampler(5 * time.Millisecond)
	start := time.Now()

	payload := buildPayload(cfg.PayloadSize)
	resp := make([]byte, len(payload))
	w := warmupCount(cfg.Messages)
	rtts := make([]time.Duration, 0, cfg.Messages)

	for i := 0; i < cfg.Messages; i++ {
		select {
		case <-ctx.Done():
			return bench.ProtocolResult{}, ctx.Err()
		default:
		}
		t0 := time.Now()
		_ = raw.SetWriteDeadline(time.Now().Add(20 * time.Second))
		if err := writeFull(cConn, payload); err != nil {
			return bench.ProtocolResult{}, err
		}
		_ = raw.SetReadDeadline(time.Now().Add(20 * time.Second))
		if err := readFull(cConn, resp); err != nil {
			return bench.ProtocolResult{}, err
		}
		if !bytes.Equal(payload, resp) {
			return bench.ProtocolResult{}, fmt.Errorf("sudoku echo mismatch")
		}
		if i >= w {
			rtts = append(rtts, time.Since(t0))
		}
	}
	_ = raw.SetDeadline(time.Time{})

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats(sudokuProtoName(pure), cfg, dur, peak, peakDelta, stats, rtts), nil
}

func sudokuProtoName(pure bool) string {
	if pure {
		return "iotbci-sudoku-pure-tcp"
	}
	return "iotbci-sudoku-packed-tcp"
}

func netbenchIdentityBundle() (masterPub ed25519.PublicKey, serverCert *iotbci.Cert, serverPriv ed25519.PrivateKey, clientCert *iotbci.Cert, clientPriv ed25519.PrivateKey, err error) {
	masterPriv := ed25519.NewKeyFromSeed(labelSeed("netbench-master-ed25519"))
	masterPub = masterPriv.Public().(ed25519.PublicKey)

	serverPriv = ed25519.NewKeyFromSeed(labelSeed("netbench-server-ed25519"))
	serverPub := serverPriv.Public().(ed25519.PublicKey)
	clientPriv = ed25519.NewKeyFromSeed(labelSeed("netbench-client-ed25519"))
	clientPub := clientPriv.Public().(ed25519.PublicKey)

	notBefore := time.Unix(1700000000, 0)
	notAfter := time.Unix(2200000000, 0)

	serverCert, err = iotbci.IssueCert(masterPriv, "netbench-server", serverPub, notBefore, notAfter, 1)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	clientCert, err = iotbci.IssueCert(masterPriv, "netbench-client", clientPub, notBefore, notAfter, 2)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return masterPub, serverCert, serverPriv, clientCert, clientPriv, nil
}

func labelSeed(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	out := make([]byte, 32)
	copy(out, sum[:])
	return out
}

func buildSudokuServerOptions(masterPub ed25519.PublicKey, serverCert *iotbci.Cert, serverPriv ed25519.PrivateKey, opts commonOpts, pure bool) *iotbci.ServerOptions {
	psk := opts.PSK
	if psk == "" {
		psk = "netbench-psk-v1"
	}
	asciiMode := "prefer_entropy"
	customTables := []string(nil)
	enablePackedUplink := true
	enablePureDownlink := false
	if pure {
		asciiMode = "prefer_ascii"
		customTables = nil
		enablePackedUplink = false
		enablePureDownlink = true
	}
	return &iotbci.ServerOptions{
		Obfs: iotbci.ObfsOptions{
			ASCII:              asciiMode,
			CustomTables:       customTables,
			PaddingMin:         opts.PaddingMin,
			PaddingMax:         opts.PaddingMax,
			EnablePureDownlink: enablePureDownlink,
			EnablePackedUplink: enablePackedUplink,
		},
		Security: iotbci.SecurityOptions{
			PSK:              psk,
			HandshakeAEAD:    iotbci.AEADAES128GCM,
			SessionAEAD:      iotbci.AEADAES128GCM,
			HandshakeTimeout: 15 * time.Second,
			TimeSkew:         10 * time.Minute,
			MaxHandshakeSize: 16 * 1024,
			ReplayWindow:     10 * time.Minute,
			ReplayCacheSize:  4096,
		},
		Identity: iotbci.IdentityOptions{
			MasterPublicKey: masterPub,
			LocalCert:       serverCert,
			LocalPrivateKey: serverPriv,
		},
	}
}

func buildSudokuClientOptions(masterPub ed25519.PublicKey, clientCert *iotbci.Cert, clientPriv ed25519.PrivateKey, opts commonOpts, pure bool) *iotbci.ClientOptions {
	psk := opts.PSK
	if psk == "" {
		psk = "netbench-psk-v1"
	}
	asciiMode := "prefer_entropy"
	customTables := []string(nil)
	enablePackedUplink := true
	enablePureDownlink := false
	if pure {
		asciiMode = "prefer_ascii"
		customTables = nil
		enablePackedUplink = false
		enablePureDownlink = true
	}
	return &iotbci.ClientOptions{
		Obfs: iotbci.ObfsOptions{
			ASCII:              asciiMode,
			CustomTables:       customTables,
			PaddingMin:         opts.PaddingMin,
			PaddingMax:         opts.PaddingMax,
			EnablePureDownlink: enablePureDownlink,
			EnablePackedUplink: enablePackedUplink,
		},
		Security: iotbci.SecurityOptions{
			PSK:              psk,
			HandshakeAEAD:    iotbci.AEADAES128GCM,
			SessionAEAD:      iotbci.AEADAES128GCM,
			HandshakeTimeout: 15 * time.Second,
			TimeSkew:         10 * time.Minute,
			MaxHandshakeSize: 16 * 1024,
		},
		Identity: iotbci.IdentityOptions{
			MasterPublicKey: masterPub,
			LocalCert:       clientCert,
			LocalPrivateKey: clientPriv,
		},
	}
}
