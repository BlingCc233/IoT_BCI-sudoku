package bench

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"
)

func RunCoAP(ctx context.Context, cfg RunConfig) (ProtocolResult, error) {
	return RunCoAPOnUDP(ctx, cfg, "127.0.0.1:0", nil)
}

func RunCoAPOnUDP(ctx context.Context, cfg RunConfig, listenAddr string, ready ReadyFunc) (ProtocolResult, error) {
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

	rawPC, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer rawPC.Close()

	pc := WrapPacketConn(rawPC, serverStats)
	raddr := rawPC.LocalAddr().(*net.UDPAddr)

	serverErr := make(chan error, 1)
	go func() {
		defer rawPC.Close()
		buf := make([]byte, 64*1024)
		for i := 0; i < cfg.Messages; i++ {
			_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				serverErr <- err
				return
			}

			req, err := parseCoAP(buf[:n])
			if err != nil {
				serverErr <- err
				return
			}
			if req.Version != 1 || req.Type != coapTypeCON || req.Code != coapCodePOST || req.Path != "bci" {
				serverErr <- fmt.Errorf("unexpected coap request: v=%d type=%d code=0x%02x path=%q", req.Version, req.Type, req.Code, req.Path)
				return
			}

			resp := coapMessage{
				Version: 1,
				Type:    coapTypeACK,
				Code:    coapCodeContent,
				MsgID:   req.MsgID,
				Token:   req.Token,
				Path:    "",
				Payload: req.Payload,
			}
			out := make([]byte, 0, 4+len(req.Token)+1+len(req.Payload))
			out = appendCoAP(out, resp)
			_ = pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := pc.WriteTo(out, addr); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	if ready != nil {
		ready(nil, []uint16{uint16(raddr.Port)})
	}

	rawConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return ProtocolResult{}, err
	}
	defer rawConn.Close()

	conn := WrapConn(rawConn, clientStats)

	payload := make([]byte, cfg.PayloadSize)
	for i := range payload {
		payload[i] = byte(i)
	}

	warmup := rttWarmupCount(cfg.Messages)
	rtts := make([]time.Duration, 0, cfg.Messages)
	buf := make([]byte, 64*1024)
	var msgID uint16 = 1
	token := []byte{0x01, 0x02, 0x03, 0x04}

	for i := 0; i < cfg.Messages; i++ {
		select {
		case <-ctx.Done():
			return ProtocolResult{}, ctx.Err()
		default:
		}

		req := coapMessage{
			Version: 1,
			Type:    coapTypeCON,
			Code:    coapCodePOST,
			MsgID:   msgID,
			Token:   token,
			Path:    "bci",
			Payload: payload,
		}
		msgID++

		out := make([]byte, 0, 4+len(token)+16+1+len(payload))
		out = appendCoAP(out, req)

		t0 := time.Now()
		rawConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := writeFull(conn, out); err != nil {
			return ProtocolResult{}, err
		}

		rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return ProtocolResult{}, err
		}
		resp, err := parseCoAP(buf[:n])
		if err != nil {
			return ProtocolResult{}, err
		}
		if resp.Version != 1 || resp.Type != coapTypeACK || resp.Code != coapCodeContent || resp.MsgID != req.MsgID || string(resp.Token) != string(req.Token) {
			return ProtocolResult{}, fmt.Errorf("unexpected coap response")
		}
		if len(resp.Payload) != len(payload) {
			return ProtocolResult{}, fmt.Errorf("coap echo length mismatch")
		}
		for j := range payload {
			if resp.Payload[j] != payload[j] {
				return ProtocolResult{}, fmt.Errorf("coap echo mismatch")
			}
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
		Name:                          "coap-udp",
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

const (
	coapTypeCON uint8 = 0
	coapTypeACK uint8 = 2

	coapCodePOST    uint8 = 0x02
	coapCodeContent uint8 = 0x45 // 2.05 Content

	coapOptUriPath uint16 = 11
)

type coapMessage struct {
	Version uint8
	Type    uint8
	Code    uint8
	MsgID   uint16
	Token   []byte
	Path    string
	Payload []byte
}

func appendCoAP(dst []byte, m coapMessage) []byte {
	tkl := len(m.Token)
	if tkl > 8 {
		panic("coap token too long")
	}
	h0 := byte((m.Version&0x3)<<6) | byte((m.Type&0x3)<<4) | byte(tkl&0xF)
	dst = append(dst, h0, byte(m.Code), 0, 0)
	binary.BigEndian.PutUint16(dst[len(dst)-2:], m.MsgID)
	dst = append(dst, m.Token...)

	// Options (Uri-Path).
	optNum := uint16(0)
	if strings.TrimSpace(m.Path) != "" {
		for _, seg := range strings.Split(strings.Trim(m.Path, "/"), "/") {
			if seg == "" {
				continue
			}
			dst = appendCoAPOption(dst, optNum, coapOptUriPath, []byte(seg))
			optNum = coapOptUriPath
		}
	}

	if len(m.Payload) > 0 {
		dst = append(dst, 0xFF)
		dst = append(dst, m.Payload...)
	}
	return dst
}

func appendCoAPOption(dst []byte, prevOpt, opt uint16, val []byte) []byte {
	delta := opt - prevOpt
	dNib, dExt := encodeCoAPNibble(delta)
	lNib, lExt := encodeCoAPNibble(uint16(len(val)))

	dst = append(dst, byte((dNib<<4)|lNib))
	dst = append(dst, dExt...)
	dst = append(dst, lExt...)
	dst = append(dst, val...)
	return dst
}

func encodeCoAPNibble(n uint16) (byte, []byte) {
	switch {
	case n <= 12:
		return byte(n), nil
	case n <= 268:
		return 13, []byte{byte(n - 13)}
	default:
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, n-269)
		return 14, ext
	}
}

func parseCoAP(b []byte) (coapMessage, error) {
	var m coapMessage
	if len(b) < 4 {
		return m, fmt.Errorf("coap: short")
	}
	v := (b[0] >> 6) & 0x3
	typ := (b[0] >> 4) & 0x3
	tkl := int(b[0] & 0xF)
	if tkl > 8 {
		return m, fmt.Errorf("coap: invalid tkl")
	}
	if len(b) < 4+tkl {
		return m, fmt.Errorf("coap: short token")
	}
	m.Version = v
	m.Type = typ
	m.Code = b[1]
	m.MsgID = binary.BigEndian.Uint16(b[2:4])
	m.Token = append([]byte(nil), b[4:4+tkl]...)

	i := 4 + tkl
	var (
		optNum uint16
		paths  []string
	)
	for i < len(b) {
		if b[i] == 0xFF {
			i++
			break
		}
		dNib := uint16(b[i] >> 4)
		lNib := uint16(b[i] & 0xF)
		i++
		if dNib == 15 || lNib == 15 {
			return m, fmt.Errorf("coap: reserved nibble")
		}
		delta, di, err := decodeCoAPNibble(dNib, b, i)
		if err != nil {
			return m, err
		}
		i = di
		l, li, err := decodeCoAPNibble(lNib, b, i)
		if err != nil {
			return m, err
		}
		i = li
		optNum += uint16(delta)
		if i+int(l) > len(b) {
			return m, fmt.Errorf("coap: option overflow")
		}
		val := b[i : i+int(l)]
		i += int(l)
		if optNum == coapOptUriPath {
			paths = append(paths, string(val))
		}
	}

	if len(paths) > 0 {
		m.Path = strings.Join(paths, "/")
	}
	if i <= len(b) {
		m.Payload = append([]byte(nil), b[i:]...)
	}
	return m, nil
}

func decodeCoAPNibble(nib uint16, b []byte, i int) (uint16, int, error) {
	switch nib {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12:
		return nib, i, nil
	case 13:
		if i >= len(b) {
			return 0, i, fmt.Errorf("coap: short ext13")
		}
		return 13 + uint16(b[i]), i + 1, nil
	case 14:
		if i+1 >= len(b) {
			return 0, i, fmt.Errorf("coap: short ext14")
		}
		return 269 + binary.BigEndian.Uint16(b[i:i+2]), i + 2, nil
	default:
		return 0, i, fmt.Errorf("coap: invalid nibble")
	}
}
