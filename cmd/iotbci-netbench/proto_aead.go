package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func runPureAEADServer(ctx context.Context, listen string, cfg bench.RunConfig, opts commonOpts) (bench.ProtocolResult, string, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}
	psk := opts.PSK
	if psk == "" {
		psk = "netbench-psk-v1"
	}

	mem, memBase := startMemPhaseSampler(5 * time.Millisecond)
	start := time.Now()

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
	c2sKey, s2cKey, c2sSalt, s2cSalt := iotbci.DerivePSKHandshakeKeys(psk)
	rc, err := iotbci.NewRecordConn(counted, iotbci.AEADChaCha20Poly1305, s2cKey[:], c2sKey[:], s2cSalt, c2sSalt)
	if err != nil {
		return bench.ProtocolResult{}, ln.Addr().String(), err
	}

	buf := make([]byte, cfg.PayloadSize)
	for i := 0; i < cfg.Messages; i++ {
		_ = raw.SetReadDeadline(time.Now().Add(15 * time.Second))
		if err := readFull(rc, buf); err != nil {
			return bench.ProtocolResult{}, ln.Addr().String(), err
		}
		_ = raw.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := writeFull(rc, buf); err != nil {
			return bench.ProtocolResult{}, ln.Addr().String(), err
		}
	}
	_ = raw.SetDeadline(time.Time{})

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats("pure-aead-tcp", cfg, dur, peak, peakDelta, stats, nil), ln.Addr().String(), nil
}

func runPureAEADClient(ctx context.Context, server string, cfg bench.RunConfig, opts commonOpts) (bench.ProtocolResult, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}
	psk := opts.PSK
	if psk == "" {
		psk = "netbench-psk-v1"
	}

	mem, memBase := startMemPhaseSampler(5 * time.Millisecond)
	start := time.Now()

	stats := &bench.WireStats{}
	raw, err := net.DialTimeout("tcp", server, 8*time.Second)
	if err != nil {
		return bench.ProtocolResult{}, err
	}
	defer raw.Close()

	counted := bench.WrapConn(raw, stats)
	c2sKey, s2cKey, c2sSalt, s2cSalt := iotbci.DerivePSKHandshakeKeys(psk)
	rc, err := iotbci.NewRecordConn(counted, iotbci.AEADChaCha20Poly1305, c2sKey[:], s2cKey[:], c2sSalt, s2cSalt)
	if err != nil {
		return bench.ProtocolResult{}, err
	}

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
		_ = raw.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := writeFull(rc, payload); err != nil {
			return bench.ProtocolResult{}, err
		}
		_ = raw.SetReadDeadline(time.Now().Add(15 * time.Second))
		if err := readFull(rc, resp); err != nil {
			return bench.ProtocolResult{}, err
		}
		if !bytes.Equal(payload, resp) {
			return bench.ProtocolResult{}, fmt.Errorf("pure-aead echo mismatch")
		}
		if i >= w {
			rtts = append(rtts, time.Since(t0))
		}
	}
	_ = raw.SetDeadline(time.Time{})

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats("pure-aead-tcp", cfg, dur, peak, peakDelta, stats, rtts), nil
}
