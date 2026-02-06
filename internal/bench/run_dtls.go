package bench

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
)

func RunDTLS(ctx context.Context, cfg RunConfig, psk string) (ProtocolResult, error) {
	return RunDTLSOnUDP(ctx, cfg, psk, "127.0.0.1:0", nil)
}

func RunDTLSOnUDP(ctx context.Context, cfg RunConfig, psk, listenAddr string, ready ReadyFunc) (ProtocolResult, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}
	if psk == "" {
		psk = "bench-psk-dtls"
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

	dtlsCfg := &dtls.Config{
		PSK: func([]byte) ([]byte, error) {
			return []byte(psk), nil
		},
		PSKIdentityHint: []byte("iotbci-bench"),
		CipherSuites:    []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
		FlightInterval:  50 * time.Millisecond,
		MTU:             1200,
	}

	serverErr := make(chan error, 1)
	go func() {
		c, err := dtls.ServerWithContext(ctx, serverConn, dtlsCfg)
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
	c, err := dtls.ClientWithContext(ctx, clientCount, dtlsCfg)
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
		Name:                          "dtls-psk-aes128gcm",
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
		WireWriteSizeSeqSample:        ws.writeSizeSeq,
		WireWriteIATMsSeqSample:       ws.writeIATMsSeq,
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

type packetConnConn struct {
	pc net.PacketConn

	mu     sync.Mutex
	remote net.Addr
}

func newPacketConnConn(pc net.PacketConn) *packetConnConn {
	return &packetConnConn{pc: pc}
}

func (c *packetConnConn) Read(b []byte) (int, error) {
	for {
		n, addr, err := c.pc.ReadFrom(b)
		if err != nil {
			return 0, err
		}
		c.mu.Lock()
		if c.remote == nil {
			c.remote = addr
		}
		remote := c.remote
		c.mu.Unlock()
		if remote == nil || addr.String() == remote.String() {
			return n, nil
		}
	}
}

func (c *packetConnConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	remote := c.remote
	c.mu.Unlock()
	if remote == nil {
		return 0, fmt.Errorf("dtls server conn: remote not set yet")
	}
	return c.pc.WriteTo(b, remote)
}

func (c *packetConnConn) Close() error { return nil }

func (c *packetConnConn) LocalAddr() net.Addr { return c.pc.LocalAddr() }

func (c *packetConnConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.remote
}

func (c *packetConnConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *packetConnConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *packetConnConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
