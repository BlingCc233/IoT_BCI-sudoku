package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
	"github.com/pion/dtls/v2"
)

func runDTLSServer(ctx context.Context, listen string, cfg bench.RunConfig, opts commonOpts) (bench.ProtocolResult, string, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}
	_ = opts.PSK

	tlsCfg, err := newSelfSignedTLSConfig()
	if err != nil {
		return bench.ProtocolResult{}, "", err
	}

	mem, memBase := startMemPhaseSampler(5 * time.Millisecond)
	start := time.Now()

	stats := &bench.WireStats{}
	rawPC, err := net.ListenPacket("udp", listen)
	if err != nil {
		return bench.ProtocolResult{}, "", err
	}
	defer rawPC.Close()
	go func() {
		<-ctx.Done()
		_ = rawPC.Close()
	}()

	pc := bench.WrapPacketConn(rawPC, stats)
	serverConn := newPacketConnConn(pc)
	cfgDTLS := &dtls.Config{
		Certificates:   []tls.Certificate{tlsCfg.Certificates[0]},
		CipherSuites:   []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		FlightInterval: 50 * time.Millisecond,
		MTU:            1200,
	}

	c, err := dtls.ServerWithContext(ctx, serverConn, cfgDTLS)
	if err != nil {
		return bench.ProtocolResult{}, rawPC.LocalAddr().String(), err
	}
	defer c.Close()

	buf := make([]byte, cfg.PayloadSize)
	for i := 0; i < cfg.Messages; i++ {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		if err := readFull(c, buf); err != nil {
			return bench.ProtocolResult{}, rawPC.LocalAddr().String(), err
		}
		_ = c.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := writeFull(c, buf); err != nil {
			return bench.ProtocolResult{}, rawPC.LocalAddr().String(), err
		}
	}
	_ = c.SetDeadline(time.Time{})

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats("dtls-psk-aes128gcm", cfg, dur, peak, peakDelta, stats, nil), rawPC.LocalAddr().String(), nil
}

func runDTLSClient(ctx context.Context, server string, cfg bench.RunConfig, opts commonOpts) (bench.ProtocolResult, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}
	_ = opts.PSK

	raddr, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return bench.ProtocolResult{}, err
	}

	mem, memBase := startMemPhaseSampler(5 * time.Millisecond)
	start := time.Now()

	stats := &bench.WireStats{}
	raw, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return bench.ProtocolResult{}, err
	}
	defer raw.Close()
	counted := bench.WrapConn(raw, stats)

	cfgDTLS := &dtls.Config{
		InsecureSkipVerify: true,
		CipherSuites:       []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		FlightInterval:     50 * time.Millisecond,
		MTU:                1200,
	}

	c, err := dtls.ClientWithContext(ctx, counted, cfgDTLS)
	if err != nil {
		return bench.ProtocolResult{}, err
	}
	defer c.Close()

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
		_ = c.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := writeFull(c, payload); err != nil {
			return bench.ProtocolResult{}, err
		}
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		if err := readFull(c, resp); err != nil {
			return bench.ProtocolResult{}, err
		}
		if !bytes.Equal(payload, resp) {
			return bench.ProtocolResult{}, fmt.Errorf("dtls echo mismatch")
		}
		if i >= w {
			rtts = append(rtts, time.Since(t0))
		}
	}
	_ = c.SetDeadline(time.Time{})

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats("dtls-psk-aes128gcm", cfg, dur, peak, peakDelta, stats, rtts), nil
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
