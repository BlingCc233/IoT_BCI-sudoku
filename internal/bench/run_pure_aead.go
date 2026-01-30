package bench

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/iotbci"
)

func RunPureAEAD(ctx context.Context, cfg RunConfig, method iotbci.AEADMethod, psk string) (ProtocolResult, error) {
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

	sRaw, cRaw := netPipe()
	defer sRaw.Close()
	defer cRaw.Close()

	sCount := WrapConn(sRaw, serverStats)
	cCount := WrapConn(cRaw, clientStats)

	c2sKey, s2cKey, c2sSalt, s2cSalt := iotbci.DerivePSKHandshakeKeys(psk)
	sConn, err := iotbci.NewRecordConn(sCount, method, s2cKey[:], c2sKey[:], s2cSalt, c2sSalt)
	if err != nil {
		return ProtocolResult{}, err
	}
	cConn, err := iotbci.NewRecordConn(cCount, method, c2sKey[:], s2cKey[:], c2sSalt, s2cSalt)
	if err != nil {
		return ProtocolResult{}, err
	}

	payload := make([]byte, cfg.PayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Echo server.
	serverErr := make(chan error, 1)
	go func() {
		buf := make([]byte, len(payload))
		for i := 0; i < cfg.Messages; i++ {
			if err := readFull(sConn, buf); err != nil {
				serverErr <- err
				return
			}
			if err := writeFull(sConn, buf); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	rtts := make([]time.Duration, 0, cfg.Messages)
	resp := make([]byte, len(payload))
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
		if !bytes.Equal(resp, payload) {
			return ProtocolResult{}, fmt.Errorf("pure-aead echo mismatch")
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

	ws := summarizeWire(clientStats, serverStats)
	durSec := dur.Seconds()
	var payloadBps, wireBps float64
	if durSec > 0 {
		payloadBps = float64(payloadBytes) / durSec
		wireBps = float64(wireBytes) / durSec
	}

	return ProtocolResult{
		Name:                          "pure-aead",
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
