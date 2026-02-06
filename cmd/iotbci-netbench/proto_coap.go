package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
)

func runCoAPServer(ctx context.Context, listen string, cfg bench.RunConfig) (bench.ProtocolResult, string, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
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
	buf := make([]byte, 64*1024)
	for i := 0; i < cfg.Messages; i++ {
		_ = rawPC.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return bench.ProtocolResult{}, rawPC.LocalAddr().String(), err
		}
		req, err := parseCoAP(buf[:n])
		if err != nil {
			return bench.ProtocolResult{}, rawPC.LocalAddr().String(), err
		}
		if req.Version != 1 || req.Type != coapTypeCON || req.Code != coapCodePOST || req.Path != "bci" {
			return bench.ProtocolResult{}, rawPC.LocalAddr().String(), fmt.Errorf("unexpected coap request")
		}
		resp := coapMessage{
			Version: 1,
			Type:    coapTypeACK,
			Code:    coapCodeContent,
			MsgID:   req.MsgID,
			Token:   req.Token,
			Payload: req.Payload,
		}
		out := make([]byte, 0, 4+len(req.Token)+1+len(req.Payload))
		out = appendCoAP(out, resp)
		_ = rawPC.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := pc.WriteTo(out, addr); err != nil {
			return bench.ProtocolResult{}, rawPC.LocalAddr().String(), err
		}
	}

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats("coap-udp", cfg, dur, peak, peakDelta, stats, nil), rawPC.LocalAddr().String(), nil
}

func runCoAPClient(ctx context.Context, server string, cfg bench.RunConfig) (bench.ProtocolResult, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}

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
	conn := bench.WrapConn(raw, stats)

	payload := buildPayload(cfg.PayloadSize)
	buf := make([]byte, 64*1024)
	token := []byte{0x01, 0x02, 0x03, 0x04}
	msgID := uint16(1)
	w := warmupCount(cfg.Messages)
	rtts := make([]time.Duration, 0, cfg.Messages)

	for i := 0; i < cfg.Messages; i++ {
		select {
		case <-ctx.Done():
			return bench.ProtocolResult{}, ctx.Err()
		default:
		}
		req := coapMessage{Version: 1, Type: coapTypeCON, Code: coapCodePOST, MsgID: msgID, Token: token, Path: "bci", Payload: payload}
		msgID++
		out := make([]byte, 0, 4+len(token)+16+1+len(payload))
		out = appendCoAP(out, req)

		t0 := time.Now()
		_ = raw.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if err := writeFull(conn, out); err != nil {
			return bench.ProtocolResult{}, err
		}
		_ = raw.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return bench.ProtocolResult{}, err
		}
		resp, err := parseCoAP(buf[:n])
		if err != nil {
			return bench.ProtocolResult{}, err
		}
		if resp.Version != 1 || resp.Type != coapTypeACK || resp.Code != coapCodeContent || resp.MsgID != req.MsgID || string(resp.Token) != string(req.Token) {
			return bench.ProtocolResult{}, fmt.Errorf("unexpected coap response")
		}
		if len(resp.Payload) != len(payload) {
			return bench.ProtocolResult{}, fmt.Errorf("coap echo length mismatch")
		}
		for j := range payload {
			if resp.Payload[j] != payload[j] {
				return bench.ProtocolResult{}, fmt.Errorf("coap echo mismatch")
			}
		}
		if i >= w {
			rtts = append(rtts, time.Since(t0))
		}
	}
	_ = raw.SetDeadline(time.Time{})

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats("coap-udp", cfg, dur, peak, peakDelta, stats, rtts), nil
}

const (
	coapTypeCON uint8 = 0
	coapTypeACK uint8 = 2

	coapCodePOST    uint8 = 0x02
	coapCodeContent uint8 = 0x45

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
