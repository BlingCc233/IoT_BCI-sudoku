package bench

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
)

func RunMQTT(ctx context.Context, cfg RunConfig) (ProtocolResult, error) {
	return RunMQTTOnTLS(ctx, cfg, "127.0.0.1:0", nil)
}

func RunMQTTOnTCP(ctx context.Context, cfg RunConfig, listenAddr string, ready ReadyFunc) (ProtocolResult, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}

	runtime.GC()
	mem := StartMemSampler(5 * time.Millisecond)
	start := time.Now()

	deviceStats := &WireStats{}
	serverStats := &WireStats{}
	brokerStats := map[string]*WireStats{}
	var brokerStatsMu sync.Mutex

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer ln.Close()

	brokerErr := make(chan error, 1)
	go func() {
		defer ln.Close()
		<-ctx.Done()
	}()

	broker := &mqttBroker{
		ln:   ln,
		subs: map[string][]*mqttPeer{},
		onConn: func(id string, stats *WireStats) {
			brokerStatsMu.Lock()
			defer brokerStatsMu.Unlock()
			brokerStats[id] = stats
		},
	}
	go func() { brokerErr <- broker.serve(ctx) }()

	if ready != nil {
		port := ln.Addr().(*net.TCPAddr).Port
		ready([]uint16{uint16(port)}, nil)
	}

	// "BCI server" client: subscribes req -> publishes resp.
	serverReady := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			serverDone <- err
			return
		}
		defer raw.Close()

		c := WrapConn(raw, serverStats)
		r := bufio.NewReader(c)
		if err := mqttConnect(c, r, "server"); err != nil {
			serverDone <- err
			return
		}
		if err := mqttSubscribe(c, r, 1, "bci/req"); err != nil {
			serverDone <- err
			return
		}
		close(serverReady)

		for i := 0; i < cfg.Messages; i++ {
			topic, payload, err := mqttReadPublish(r)
			if err != nil {
				serverDone <- err
				return
			}
			if topic != "bci/req" {
				serverDone <- fmt.Errorf("mqtt server: unexpected topic: %q", topic)
				return
			}
			if err := mqttPublish(c, "bci/resp", payload); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	// Device client: publishes req -> waits resp.
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer raw.Close()

	c := WrapConn(raw, deviceStats)
	r := bufio.NewReader(c)
	if err := mqttConnect(c, r, "device"); err != nil {
		return ProtocolResult{}, err
	}
	if err := mqttSubscribe(c, r, 1, "bci/resp"); err != nil {
		return ProtocolResult{}, err
	}

	select {
	case <-serverReady:
	case <-ctx.Done():
		return ProtocolResult{}, ctx.Err()
	}

	payload := make([]byte, cfg.PayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	rtts := make([]time.Duration, 0, cfg.Messages)
	warmup := rttWarmupCount(cfg.Messages)
	for i := 0; i < cfg.Messages; i++ {
		select {
		case <-ctx.Done():
			return ProtocolResult{}, ctx.Err()
		default:
		}
		t0 := time.Now()
		if err := mqttPublish(c, "bci/req", payload); err != nil {
			return ProtocolResult{}, err
		}
		topic, resp, err := mqttReadPublish(r)
		if err != nil {
			return ProtocolResult{}, err
		}
		if topic != "bci/resp" {
			return ProtocolResult{}, fmt.Errorf("mqtt device: unexpected topic: %q", topic)
		}
		if len(resp) != len(payload) {
			return ProtocolResult{}, fmt.Errorf("mqtt echo length mismatch")
		}
		for j := range payload {
			if resp[j] != payload[j] {
				return ProtocolResult{}, fmt.Errorf("mqtt echo mismatch")
			}
		}
		if i >= warmup {
			rtts = append(rtts, time.Since(t0))
		}
	}

	if err := <-serverDone; err != nil {
		return ProtocolResult{}, err
	}
	_ = ln.Close()
	_ = raw.Close()

	select {
	case err := <-brokerErr:
		if err != nil && ctx.Err() == nil {
			// Ignore accept loop errors during shutdown.
		}
	default:
	}

	peak := mem.Stop()
	dur := time.Since(start)

	brokerStatsMu.Lock()
	bsDevice := brokerStats["device"]
	bsServer := brokerStats["server"]
	brokerStatsMu.Unlock()
	if bsDevice == nil || bsServer == nil {
		return ProtocolResult{}, fmt.Errorf("mqtt broker stats missing (got device=%v server=%v)", bsDevice != nil, bsServer != nil)
	}

	wireBytes := deviceStats.BytesWritten.Load() + serverStats.BytesWritten.Load() + bsDevice.BytesWritten.Load() + bsServer.BytesWritten.Load()
	payloadBytes := int64(cfg.Messages * cfg.PayloadSize * 2)

	var freq [256]uint64
	acc := func(s *WireStats) {
		f := s.SnapshotWrittenFreq()
		for i := 0; i < 256; i++ {
			freq[i] += f[i]
		}
	}
	acc(deviceStats)
	acc(serverStats)
	acc(bsDevice)
	acc(bsServer)
	stats := ComputeByteStats(freq)

	avg := avgDuration(rtts)
	p95 := percentileDuration(rtts, 0.95)

	ws := summarizeWireMany(deviceStats, serverStats, bsDevice, bsServer)
	durSec := dur.Seconds()
	var payloadBps, wireBps float64
	if durSec > 0 {
		payloadBps = float64(payloadBytes) / durSec
		wireBps = float64(wireBytes) / durSec
	}

	return ProtocolResult{
		Name:                          "mqtt-3.1.1-qos0",
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
		WireEntropy:                   stats.Entropy,
		WireASCIIRatio:                stats.ASCIIRatio,
		PeakHeapAllocBytes:            peak.HeapAlloc,
		PeakHeapInuseBytes:            peak.HeapInuse,
		PeakSysBytes:                  peak.Sys,
		PayloadThroughputBps:          payloadBps,
		WireThroughputBps:             wireBps,
		DurationMillis:                float64(dur) / float64(time.Millisecond),
	}, nil
}

func RunMQTTOnTLS(ctx context.Context, cfg RunConfig, listenAddr string, ready ReadyFunc) (ProtocolResult, error) {
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
	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certs.ServerCert},
	}
	clientTLS := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    certs.CAPool,
		// When using tls.Client (not tls.Dial), ServerName must be set.
		// Go treats IP strings specially and will verify against IP SANs.
		ServerName: "127.0.0.1",
	}

	runtime.GC()
	mem := StartMemSampler(5 * time.Millisecond)
	start := time.Now()

	deviceStats := &WireStats{}
	serverStats := &WireStats{}
	brokerStats := map[string]*WireStats{}
	var brokerStatsMu sync.Mutex

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer ln.Close()

	brokerErr := make(chan error, 1)
	go func() {
		defer ln.Close()
		<-ctx.Done()
	}()

	broker := &mqttBroker{
		ln:        ln,
		subs:      map[string][]*mqttPeer{},
		tlsConfig: serverTLS,
		onConn: func(id string, stats *WireStats) {
			brokerStatsMu.Lock()
			defer brokerStatsMu.Unlock()
			brokerStats[id] = stats
		},
	}
	go func() { brokerErr <- broker.serve(ctx) }()

	if ready != nil {
		port := ln.Addr().(*net.TCPAddr).Port
		ready([]uint16{uint16(port)}, nil)
	}

	// "BCI server" client: subscribes req -> publishes resp.
	serverReady := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		defer close(serverDone)
		raw, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			serverDone <- err
			return
		}
		defer raw.Close()

		counted := WrapConn(raw, serverStats)
		tc := tls.Client(counted, clientTLS)
		_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tc.HandshakeContext(ctx); err != nil {
			serverDone <- err
			return
		}
		_ = tc.SetDeadline(time.Time{})

		r := bufio.NewReader(tc)
		if err := mqttConnect(tc, r, "server"); err != nil {
			serverDone <- err
			return
		}
		if err := mqttSubscribe(tc, r, 1, "bci/req"); err != nil {
			serverDone <- err
			return
		}
		close(serverReady)

		for i := 0; i < cfg.Messages; i++ {
			topic, payload, err := mqttReadPublish(r)
			if err != nil {
				serverDone <- err
				return
			}
			if topic != "bci/req" {
				serverDone <- fmt.Errorf("mqtt server: unexpected topic: %q", topic)
				return
			}
			if err := mqttPublish(tc, "bci/resp", payload); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	// Device client: publishes req -> waits resp.
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer raw.Close()

	counted := WrapConn(raw, deviceStats)
	tc := tls.Client(counted, clientTLS)
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		return ProtocolResult{}, err
	}
	_ = tc.SetDeadline(time.Time{})

	r := bufio.NewReader(tc)
	if err := mqttConnect(tc, r, "device"); err != nil {
		return ProtocolResult{}, err
	}
	if err := mqttSubscribe(tc, r, 1, "bci/resp"); err != nil {
		return ProtocolResult{}, err
	}

	select {
	case <-serverReady:
	case <-ctx.Done():
		return ProtocolResult{}, ctx.Err()
	}

	payload := make([]byte, cfg.PayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	rtts := make([]time.Duration, 0, cfg.Messages)
	warmup := rttWarmupCount(cfg.Messages)
	for i := 0; i < cfg.Messages; i++ {
		select {
		case <-ctx.Done():
			return ProtocolResult{}, ctx.Err()
		default:
		}
		t0 := time.Now()
		if err := mqttPublish(tc, "bci/req", payload); err != nil {
			return ProtocolResult{}, err
		}
		topic, resp, err := mqttReadPublish(r)
		if err != nil {
			return ProtocolResult{}, err
		}
		if topic != "bci/resp" {
			return ProtocolResult{}, fmt.Errorf("mqtt device: unexpected topic: %q", topic)
		}
		if len(resp) != len(payload) {
			return ProtocolResult{}, fmt.Errorf("mqtt echo length mismatch")
		}
		for j := range payload {
			if resp[j] != payload[j] {
				return ProtocolResult{}, fmt.Errorf("mqtt echo mismatch")
			}
		}
		if i >= warmup {
			rtts = append(rtts, time.Since(t0))
		}
	}

	if err := <-serverDone; err != nil {
		return ProtocolResult{}, err
	}
	_ = ln.Close()
	_ = raw.Close()

	select {
	case err := <-brokerErr:
		if err != nil && ctx.Err() == nil {
			// Ignore accept loop errors during shutdown.
		}
	default:
	}

	peak := mem.Stop()
	dur := time.Since(start)

	brokerStatsMu.Lock()
	bsDevice := brokerStats["device"]
	bsServer := brokerStats["server"]
	brokerStatsMu.Unlock()
	if bsDevice == nil || bsServer == nil {
		return ProtocolResult{}, fmt.Errorf("mqtt broker stats missing (got device=%v server=%v)", bsDevice != nil, bsServer != nil)
	}

	wireBytes := deviceStats.BytesWritten.Load() + serverStats.BytesWritten.Load() + bsDevice.BytesWritten.Load() + bsServer.BytesWritten.Load()
	payloadBytes := int64(cfg.Messages * cfg.PayloadSize * 2)

	var freq [256]uint64
	acc := func(s *WireStats) {
		f := s.SnapshotWrittenFreq()
		for i := 0; i < 256; i++ {
			freq[i] += f[i]
		}
	}
	acc(deviceStats)
	acc(serverStats)
	acc(bsDevice)
	acc(bsServer)
	stats := ComputeByteStats(freq)

	avg := avgDuration(rtts)
	p95 := percentileDuration(rtts, 0.95)

	ws := summarizeWireMany(deviceStats, serverStats, bsDevice, bsServer)
	durSec := dur.Seconds()
	var payloadBps, wireBps float64
	if durSec > 0 {
		payloadBps = float64(payloadBytes) / durSec
		wireBps = float64(wireBytes) / durSec
	}

	return ProtocolResult{
		Name:                          "mqtt-3.1.1-qos0-tls",
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
		WireEntropy:                   stats.Entropy,
		WireASCIIRatio:                stats.ASCIIRatio,
		PeakHeapAllocBytes:            peak.HeapAlloc,
		PeakHeapInuseBytes:            peak.HeapInuse,
		PeakSysBytes:                  peak.Sys,
		PayloadThroughputBps:          payloadBps,
		WireThroughputBps:             wireBps,
		DurationMillis:                float64(dur) / float64(time.Millisecond),
	}, nil
}

type mqttBroker struct {
	ln net.Listener

	mu   sync.Mutex
	subs map[string][]*mqttPeer

	onConn func(clientID string, stats *WireStats)

	tlsConfig *tls.Config
}

type mqttPeer struct {
	id    string
	conn  net.Conn
	br    *bufio.Reader
	stats *WireStats

	wmu sync.Mutex
}

func (b *mqttBroker) serve(ctx context.Context) error {
	if b.ln == nil {
		return fmt.Errorf("mqtt broker: nil listener")
	}
	for {
		raw, err := b.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go b.handleConn(ctx, raw)
	}
}

func (b *mqttBroker) handleConn(ctx context.Context, raw net.Conn) {
	defer raw.Close()

	stats := &WireStats{}
	counted := WrapConn(raw, stats)
	conn := counted
	if b.tlsConfig != nil {
		tlsConn := tls.Server(counted, b.tlsConfig)
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return
		}
		_ = tlsConn.SetDeadline(time.Time{})
		conn = tlsConn
	}
	r := bufio.NewReader(conn)

	pt, _, body, err := mqttReadPacket(r)
	if err != nil {
		return
	}
	if pt != mqttTypeCONNECT {
		return
	}
	id, err := mqttParseConnect(body)
	if err != nil {
		return
	}
	p := &mqttPeer{id: id, conn: conn, br: r, stats: stats}
	if b.onConn != nil {
		b.onConn(id, stats)
	}
	_ = mqttWriteConnAck(p.conn)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pt, _, body, err := mqttReadPacket(p.br)
		if err != nil {
			return
		}
		switch pt {
		case mqttTypeSUBSCRIBE:
			pid, topic, err := mqttParseSubscribe(body)
			if err != nil {
				return
			}
			b.mu.Lock()
			b.subs[topic] = append(b.subs[topic], p)
			b.mu.Unlock()
			_ = mqttWriteSubAck(p.conn, pid)
		case mqttTypePUBLISH:
			topic, payload, err := mqttParsePublish(body)
			if err != nil {
				return
			}
			b.mu.Lock()
			subs := append([]*mqttPeer(nil), b.subs[topic]...)
			b.mu.Unlock()
			for _, s := range subs {
				s.wmu.Lock()
				_ = mqttPublish(s.conn, topic, payload)
				s.wmu.Unlock()
			}
		case mqttTypePINGREQ:
			p.wmu.Lock()
			_ = mqttWritePingResp(p.conn)
			p.wmu.Unlock()
		case mqttTypeDISCONNECT:
			return
		default:
			// ignore
		}
	}
}

const (
	mqttTypeCONNECT    byte = 1
	mqttTypeCONNACK    byte = 2
	mqttTypePUBLISH    byte = 3
	mqttTypeSUBSCRIBE  byte = 8
	mqttTypeSUBACK     byte = 9
	mqttTypePINGREQ    byte = 12
	mqttTypePINGRESP   byte = 13
	mqttTypeDISCONNECT byte = 14
)

func mqttConnect(w io.Writer, r *bufio.Reader, clientID string) error {
	body := make([]byte, 0, 64)
	body = appendString(body, "MQTT")
	body = append(body, 4)    // protocol level 4 (3.1.1)
	body = append(body, 0x02) // clean session
	body = append(body, 0, 30)
	body = appendString(body, clientID)
	if err := mqttWritePacket(w, 0x10, body); err != nil {
		return err
	}
	pt, _, resp, err := mqttReadPacket(r)
	if err != nil {
		return err
	}
	if pt != mqttTypeCONNACK || len(resp) < 2 || resp[1] != 0 {
		return fmt.Errorf("mqtt: connack failed")
	}
	return nil
}

func mqttSubscribe(w io.Writer, r *bufio.Reader, packetID uint16, topic string) error {
	body := make([]byte, 0, 64)
	body = binary.BigEndian.AppendUint16(body, packetID)
	body = appendString(body, topic)
	body = append(body, 0x00) // QoS 0
	if err := mqttWritePacket(w, 0x82, body); err != nil {
		return err
	}
	pt, _, resp, err := mqttReadPacket(r)
	if err != nil {
		return err
	}
	if pt != mqttTypeSUBACK || len(resp) < 3 || binary.BigEndian.Uint16(resp[:2]) != packetID {
		return fmt.Errorf("mqtt: suback failed")
	}
	return nil
}

func mqttPublish(w io.Writer, topic string, payload []byte) error {
	body := make([]byte, 0, 2+len(topic)+len(payload))
	body = appendString(body, topic)
	body = append(body, payload...)
	return mqttWritePacket(w, 0x30, body)
}

func mqttReadPublish(r *bufio.Reader) (topic string, payload []byte, err error) {
	for {
		pt, _, body, err := mqttReadPacket(r)
		if err != nil {
			return "", nil, err
		}
		if pt != mqttTypePUBLISH {
			continue
		}
		topic, payload, err := mqttParsePublish(body)
		return topic, payload, err
	}
}

func mqttWriteConnAck(w io.Writer) error {
	return mqttWritePacket(w, 0x20, []byte{0x00, 0x00})
}

func mqttWriteSubAck(w io.Writer, packetID uint16) error {
	body := make([]byte, 0, 4)
	body = binary.BigEndian.AppendUint16(body, packetID)
	body = append(body, 0x00)
	return mqttWritePacket(w, 0x90, body)
}

func mqttWritePingResp(w io.Writer) error {
	return mqttWritePacket(w, 0xD0, nil)
}

func mqttReadPacket(r *bufio.Reader) (pt byte, flags byte, body []byte, err error) {
	h, err := r.ReadByte()
	if err != nil {
		return 0, 0, nil, err
	}
	pt = h >> 4
	flags = h & 0x0F

	rl, err := mqttReadRemainingLength(r)
	if err != nil {
		return 0, 0, nil, err
	}
	if rl < 0 || rl > 16*1024*1024 {
		return 0, 0, nil, fmt.Errorf("mqtt: invalid remaining length %d", rl)
	}
	body = make([]byte, rl)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, 0, nil, err
	}
	return pt, flags, body, nil
}

func mqttWritePacket(w io.Writer, fixedHeader byte, body []byte) error {
	if _, err := w.Write([]byte{fixedHeader}); err != nil {
		return err
	}
	if err := mqttWriteRemainingLength(w, len(body)); err != nil {
		return err
	}
	return writeFull(w, body)
}

func mqttReadRemainingLength(r *bufio.Reader) (int, error) {
	mult := 1
	val := 0
	for i := 0; i < 4; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		val += int(b&127) * mult
		if (b & 128) == 0 {
			return val, nil
		}
		mult *= 128
	}
	return 0, fmt.Errorf("mqtt: remaining length overflow")
}

func mqttWriteRemainingLength(w io.Writer, n int) error {
	for {
		d := byte(n % 128)
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		if _, err := w.Write([]byte{d}); err != nil {
			return err
		}
		if n <= 0 {
			return nil
		}
	}
}

func mqttParseConnect(body []byte) (string, error) {
	// protocol name
	_, rest, err := readString(body)
	if err != nil {
		return "", err
	}
	if len(rest) < 4 {
		return "", fmt.Errorf("mqtt: connect short")
	}
	// level := rest[0]
	// flags := rest[1]
	// keepalive := binary.BigEndian.Uint16(rest[2:4])
	rest = rest[4:]
	id, _, err := readString(rest)
	return id, err
}

func mqttParseSubscribe(body []byte) (packetID uint16, topic string, err error) {
	if len(body) < 2 {
		return 0, "", fmt.Errorf("mqtt: subscribe short")
	}
	packetID = binary.BigEndian.Uint16(body[:2])
	topic, rest, err := readString(body[2:])
	if err != nil {
		return 0, "", err
	}
	if len(rest) < 1 {
		return 0, "", fmt.Errorf("mqtt: subscribe missing qos")
	}
	return packetID, topic, nil
}

func mqttParsePublish(body []byte) (topic string, payload []byte, err error) {
	topic, rest, err := readString(body)
	if err != nil {
		return "", nil, err
	}
	return topic, rest, nil
}

func appendString(dst []byte, s string) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(s)))
	dst = append(dst, s...)
	return dst
}

func readString(b []byte) (s string, rest []byte, err error) {
	if len(b) < 2 {
		return "", nil, fmt.Errorf("mqtt: short string")
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if n < 0 || n > len(b) {
		return "", nil, fmt.Errorf("mqtt: string length overflow")
	}
	return string(b[:n]), b[n:], nil
}
