package bench

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/pion/dtls/v2"
)

func RunDTLSCertECDHE(ctx context.Context, cfg RunConfig) (ProtocolResult, error) {
	return RunDTLSCertECDHEOnUDP(ctx, cfg, "127.0.0.1:0", nil)
}

func RunDTLSCertECDHEOnUDP(ctx context.Context, cfg RunConfig, listenAddr string, ready ReadyFunc) (ProtocolResult, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}

	certs, err := newLocalCertBundle()
	if err != nil {
		return ProtocolResult{}, err
	}

	// One CA issues both server/client certs, mutual authentication enabled.
	serverCfg := &dtls.Config{
		Certificates: []tls.Certificate{certs.ServerCert},
		ClientCAs:    certs.CAPool,
		ClientAuth:   dtls.RequireAndVerifyClientCert,
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		FlightInterval: 50 * time.Millisecond,
		MTU:            1200,
	}
	clientCfg := &dtls.Config{
		Certificates: []tls.Certificate{certs.ClientCert},
		RootCAs:      certs.CAPool,
		ServerName:   "127.0.0.1",
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		FlightInterval: 50 * time.Millisecond,
		MTU:            1200,
	}

	runtime.GC()
	mem := StartMemSampler(5 * time.Millisecond)
	start := time.Now()

	clientStats := &WireStats{}
	serverStats := &WireStats{}

	rawPC, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer rawPC.Close()

	pc := WrapPacketConn(rawPC, serverStats)
	serverConn := newPacketConnConn(pc)

	serverErr := make(chan error, 1)
	go func() {
		c, err := dtls.ServerWithContext(ctx, serverConn, serverCfg)
		if err != nil {
			serverErr <- err
			return
		}
		defer c.Close()

		buf := make([]byte, cfg.PayloadSize)
		for i := 0; i < cfg.Messages; i++ {
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if err := readFull(c, buf); err != nil {
				serverErr <- err
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if err := writeFull(c, buf); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	raddr, ok := rawPC.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ProtocolResult{}, fmt.Errorf("unexpected local addr type: %T", rawPC.LocalAddr())
	}
	if ready != nil {
		ready(nil, []uint16{uint16(raddr.Port)})
	}

	rawClientConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer rawClientConn.Close()

	clientCount := WrapConn(rawClientConn, clientStats)
	c, err := dtls.ClientWithContext(ctx, clientCount, clientCfg)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer c.Close()

	payload := make([]byte, cfg.PayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	resp := make([]byte, len(payload))

	rtts := make([]time.Duration, 0, cfg.Messages)
	warmup := rttWarmupCount(cfg.Messages)
	for i := 0; i < cfg.Messages; i++ {
		select {
		case <-ctx.Done():
			return ProtocolResult{}, ctx.Err()
		default:
		}
		t0 := time.Now()
		_ = c.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if err := writeFull(c, payload); err != nil {
			return ProtocolResult{}, err
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err := readFull(c, resp); err != nil {
			return ProtocolResult{}, err
		}
		if !bytes.Equal(resp, payload) {
			return ProtocolResult{}, fmt.Errorf("dtls echo mismatch")
		}
		if i >= warmup {
			rtts = append(rtts, time.Since(t0))
		}
	}
	if err := <-serverErr; err != nil {
		return ProtocolResult{}, err
	}

	peak := mem.Stop()
	dur := time.Since(start)

	wireBytes := clientStats.BytesWritten.Load() + serverStats.BytesWritten.Load()
	payloadBytes := int64(cfg.Messages * cfg.PayloadSize * 2)

	var freq [256]uint64
	f1 := clientStats.SnapshotWrittenFreq()
	f2 := serverStats.SnapshotWrittenFreq()
	for i := 0; i < 256; i++ {
		freq[i] = f1[i] + f2[i]
	}
	bs := ComputeByteStats(freq)

	avg := avgDuration(rtts)
	p95 := percentileDuration(rtts, 0.95)

	ws := summarizeWire(clientStats, serverStats)
	durSec := dur.Seconds()
	var payloadBps, wireBps float64
	if durSec > 0 {
		payloadBps = float64(payloadBytes) / durSec
		wireBps = float64(wireBytes) / durSec
	}

	return ProtocolResult{
		Name:                          "dtls-ecdhe-ecdsa-aes128gcm",
		Messages:                      cfg.Messages,
		PayloadSize:                   cfg.PayloadSize,
		PayloadBytesTotal:             payloadBytes,
		WireBytesTotal:                wireBytes,
		OverheadRatio:                 float64(wireBytes) / float64(payloadBytes),
		AvgRTTMillis:                  float64(avg) / float64(time.Millisecond),
		P95RTTMillis:                  float64(p95) / float64(time.Millisecond),
		WireWriteCalls:                ws.writeCalls,
		WireReadCalls:                 ws.readCalls,
		WireWriteSizeBinsLog2:         ws.writeSizeBins,
		WireWriteInterArrivalMsBinsL2: ws.writeIATBins,
		WireActiveDurationMillis:      ws.activeDurationMillis,
		WireEntropy:                   bs.Entropy,
		WireASCIIRatio:                bs.ASCIIRatio,
		PeakHeapAllocBytes:            peak.HeapAlloc,
		PeakHeapInuseBytes:            peak.HeapInuse,
		PeakSysBytes:                  peak.Sys,
		PayloadThroughputBps:          payloadBps,
		WireThroughputBps:             wireBps,
		DurationMillis:                float64(dur) / float64(time.Millisecond),
	}, nil
}
