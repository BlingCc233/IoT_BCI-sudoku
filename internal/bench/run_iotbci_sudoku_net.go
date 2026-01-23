package bench

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"net"
	"runtime"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func RunIoTBCISudokuOnTCP(ctx context.Context, cfg RunConfig, enablePureDownlink bool, paddingMin, paddingMax int, listenAddr string, ready ReadyFunc) (ProtocolResult, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}

	runtime.GC()
	mem := StartMemSampler(5 * time.Millisecond)
	start := time.Now()

	clientStats := &WireStats{}
	serverStats := &WireStats{}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	// Identity & certs (master-signed).
	masterPub, masterPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now()
	serverCert, err := iotbci.IssueCert(masterPriv, "server-1", serverPub, now.Add(-time.Hour), now.Add(24*time.Hour), 1)
	if err != nil {
		return ProtocolResult{}, err
	}
	clientCert, err := iotbci.IssueCert(masterPriv, "device-1", clientPub, now.Add(-time.Hour), now.Add(24*time.Hour), 2)
	if err != nil {
		return ProtocolResult{}, err
	}

	// Shared PSK for handshake protection + obfs seed.
	sum := sha256.Sum256([]byte(now.String()))
	psk := "bench-psk:" + hex8(sum[:])

	serverOpts := &iotbci.ServerOptions{
		Obfs: iotbci.ObfsOptions{
			ASCII:              "prefer_entropy",
			CustomTables:       []string{"xppppxvv", "vppxppvx"},
			PaddingMin:         paddingMin,
			PaddingMax:         paddingMax,
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
	}

	clientOpts := &iotbci.ClientOptions{
		Obfs: iotbci.ObfsOptions{
			ASCII:              "prefer_entropy",
			CustomTables:       []string{"xppppxvv", "vppxppvx"},
			PaddingMin:         paddingMin,
			PaddingMax:         paddingMax,
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

	// Server handshake + echo loop.
	serverErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer raw.Close()

		sCount := WrapConn(raw, serverStats)
		sConn, _, err := iotbci.ServerHandshake(ctx, sCount, serverOpts)
		if err != nil {
			serverErr <- err
			return
		}
		defer sConn.Close()

		payload := make([]byte, cfg.PayloadSize)
		for i := 0; i < cfg.Messages; i++ {
			if err := readFull(sConn, payload); err != nil {
				serverErr <- err
				return
			}
			if err := writeFull(sConn, payload); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	if ready != nil {
		ready([]uint16{uint16(port)}, nil)
	}

	rawClient, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer rawClient.Close()

	cCount := WrapConn(rawClient, clientStats)
	cConn, _, err := iotbci.ClientHandshake(ctx, cCount, clientOpts)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer cConn.Close()

	payload := make([]byte, cfg.PayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	resp := make([]byte, len(payload))

	rtts := make([]time.Duration, 0, cfg.Messages)
	for i := 0; i < cfg.Messages; i++ {
		select {
		case <-ctx.Done():
			return ProtocolResult{}, ctx.Err()
		default:
		}
		t0 := time.Now()
		if err := writeFull(cConn, payload); err != nil {
			return ProtocolResult{}, err
		}
		if err := readFull(cConn, resp); err != nil {
			return ProtocolResult{}, err
		}
		rtts = append(rtts, time.Since(t0))
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

	name := "iotbci-sudoku"
	if enablePureDownlink {
		name += "-pure"
	} else {
		name += "-packed"
	}
	name += "-tcp"

	ws := summarizeWire(clientStats, serverStats)
	durSec := dur.Seconds()
	var payloadBps, wireBps float64
	if durSec > 0 {
		payloadBps = float64(payloadBytes) / durSec
		wireBps = float64(wireBytes) / durSec
	}

	return ProtocolResult{
		Name:                          name,
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
