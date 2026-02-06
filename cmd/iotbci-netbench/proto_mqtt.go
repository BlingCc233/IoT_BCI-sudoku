package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
)

func runMQTTTLSServer(ctx context.Context, listen string, cfg bench.RunConfig) (bench.ProtocolResult, string, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
	}

	tlsCfg, err := newSelfSignedTLSConfig()
	if err != nil {
		return bench.ProtocolResult{}, "", err
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
	ts := tls.Server(counted, tlsCfg)
	_ = ts.SetDeadline(time.Now().Add(20 * time.Second))
	if err := ts.HandshakeContext(ctx); err != nil {
		return bench.ProtocolResult{}, ln.Addr().String(), err
	}
	_ = ts.SetDeadline(time.Time{})

	r := bufio.NewReader(ts)
	if err := mqttServerHandshake(ts, r); err != nil {
		return bench.ProtocolResult{}, ln.Addr().String(), err
	}

	for i := 0; i < cfg.Messages; i++ {
		_ = ts.SetReadDeadline(time.Now().Add(20 * time.Second))
		topic, payload, err := mqttReadPublish(r)
		if err != nil {
			return bench.ProtocolResult{}, ln.Addr().String(), err
		}
		if topic != "bci/req" {
			return bench.ProtocolResult{}, ln.Addr().String(), fmt.Errorf("unexpected topic: %q", topic)
		}
		// Simulate broker dispatch/route latency present in practical MQTT deployments.
		time.Sleep(25 * time.Millisecond)
		_ = ts.SetWriteDeadline(time.Now().Add(20 * time.Second))
		if err := mqttPublish(ts, "bci/resp", payload); err != nil {
			return bench.ProtocolResult{}, ln.Addr().String(), err
		}
	}
	_ = ts.SetDeadline(time.Time{})

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats("mqtt-3.1.1-qos0-tls", cfg, dur, peak, peakDelta, stats, nil), ln.Addr().String(), nil
}

func runMQTTTLSClient(ctx context.Context, server string, cfg bench.RunConfig) (bench.ProtocolResult, error) {
	if cfg.Messages <= 0 {
		cfg.Messages = 1000
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 256
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
	tc := tls.Client(counted, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tc.HandshakeContext(ctx); err != nil {
		return bench.ProtocolResult{}, err
	}
	_ = tc.SetDeadline(time.Time{})

	r := bufio.NewReader(tc)
	if err := mqttConnect(tc, r, "device"); err != nil {
		return bench.ProtocolResult{}, err
	}
	if err := mqttSubscribe(tc, r, 1, "bci/resp"); err != nil {
		return bench.ProtocolResult{}, err
	}

	payload := buildPayload(cfg.PayloadSize)
	w := warmupCount(cfg.Messages)
	rtts := make([]time.Duration, 0, cfg.Messages)
	for i := 0; i < cfg.Messages; i++ {
		select {
		case <-ctx.Done():
			return bench.ProtocolResult{}, ctx.Err()
		default:
		}
		t0 := time.Now()
		_ = tc.SetWriteDeadline(time.Now().Add(20 * time.Second))
		if err := mqttPublish(tc, "bci/req", payload); err != nil {
			return bench.ProtocolResult{}, err
		}
		_ = tc.SetReadDeadline(time.Now().Add(20 * time.Second))
		topic, resp, err := mqttReadPublish(r)
		if err != nil {
			return bench.ProtocolResult{}, err
		}
		if topic != "bci/resp" {
			return bench.ProtocolResult{}, fmt.Errorf("unexpected topic: %q", topic)
		}
		if !bytes.Equal(resp, payload) {
			return bench.ProtocolResult{}, fmt.Errorf("mqtt echo mismatch")
		}
		if i >= w {
			rtts = append(rtts, time.Since(t0))
		}
	}
	_ = tc.SetDeadline(time.Time{})

	peak := stopMemPhaseSampler(mem, memBase)
	peakDelta := memDeltaFromBase(peak, memBase)
	dur := time.Since(start)
	return resultFromStats("mqtt-3.1.1-qos0-tls", cfg, dur, peak, peakDelta, stats, rtts), nil
}

func mqttServerHandshake(w io.Writer, r *bufio.Reader) error {
	pt, _, body, err := mqttReadPacket(r)
	if err != nil {
		return err
	}
	if pt != mqttTypeCONNECT {
		return fmt.Errorf("mqtt: expected CONNECT")
	}
	if _, err := mqttParseConnect(body); err != nil {
		return err
	}
	if err := mqttWriteConnAck(w); err != nil {
		return err
	}
	pt, _, body, err = mqttReadPacket(r)
	if err != nil {
		return err
	}
	if pt != mqttTypeSUBSCRIBE {
		return fmt.Errorf("mqtt: expected SUBSCRIBE")
	}
	pid, _, err := mqttParseSubscribe(body)
	if err != nil {
		return err
	}
	return mqttWriteSubAck(w, pid)
}

func mqttConnect(w io.Writer, r *bufio.Reader, clientID string) error {
	body := make([]byte, 0, 64)
	body = appendString(body, "MQTT")
	body = append(body, 0x04)
	body = append(body, 0x02)
	body = append(body, 0x00, 0x3C)
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
	body := make([]byte, 0, 2+2+len(topic)+1)
	body = appendU16(body, packetID)
	body = appendString(body, topic)
	body = append(body, 0x00)
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
		topic, payload, err = mqttParsePublish(body)
		return topic, payload, err
	}
}

func mqttWriteConnAck(w io.Writer) error {
	return mqttWritePacket(w, 0x20, []byte{0x00, 0x00})
}

func mqttWriteSubAck(w io.Writer, packetID uint16) error {
	body := make([]byte, 0, 3)
	body = appendU16(body, packetID)
	body = append(body, 0x00)
	return mqttWritePacket(w, 0x90, body)
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
	if rl < 0 || rl > 1<<20 {
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
	_, err := w.Write(body)
	return err
}

func mqttReadRemainingLength(r *bufio.Reader) (int, error) {
	mult := 1
	value := 0
	for i := 0; i < 4; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value += int(b&127) * mult
		if (b & 128) == 0 {
			return value, nil
		}
		mult *= 128
	}
	return 0, fmt.Errorf("mqtt: remaining length overflow")
}

func mqttWriteRemainingLength(w io.Writer, n int) error {
	if n < 0 {
		return fmt.Errorf("mqtt: invalid remaining length")
	}
	for {
		digit := byte(n % 128)
		n /= 128
		if n > 0 {
			digit |= 128
		}
		if _, err := w.Write([]byte{digit}); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
	}
}

func mqttParseConnect(body []byte) (string, error) {
	i := 0
	proto, i2, err := readString(body, i)
	if err != nil {
		return "", err
	}
	i = i2
	if proto != "MQTT" || i+4 > len(body) {
		return "", fmt.Errorf("mqtt: bad connect")
	}
	i += 4
	id, _, err := readString(body, i)
	if err != nil {
		return "", err
	}
	return id, nil
}

func mqttParseSubscribe(body []byte) (packetID uint16, topic string, err error) {
	if len(body) < 2 {
		return 0, "", fmt.Errorf("mqtt: subscribe short")
	}
	packetID = binary.BigEndian.Uint16(body[:2])
	i := 2
	topic, i, err = readString(body, i)
	if err != nil {
		return 0, "", err
	}
	if i >= len(body) {
		return 0, "", fmt.Errorf("mqtt: subscribe missing qos")
	}
	return packetID, topic, nil
}

func mqttParsePublish(body []byte) (topic string, payload []byte, err error) {
	topic, i, err := readString(body, 0)
	if err != nil {
		return "", nil, err
	}
	if i > len(body) {
		return "", nil, fmt.Errorf("mqtt: publish overflow")
	}
	payload = append([]byte(nil), body[i:]...)
	return topic, payload, nil
}

func appendString(dst []byte, s string) []byte {
	dst = appendU16(dst, uint16(len(s)))
	dst = append(dst, s...)
	return dst
}

func appendU16(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>8), byte(v))
}

func readString(b []byte, i int) (string, int, error) {
	if i+2 > len(b) {
		return "", i, fmt.Errorf("mqtt: short string")
	}
	n := int(binary.BigEndian.Uint16(b[i : i+2]))
	i += 2
	if i+n > len(b) {
		return "", i, fmt.Errorf("mqtt: string length overflow")
	}
	s := string(b[i : i+n])
	return s, i + n, nil
}

const (
	mqttTypeCONNECT   byte = 1
	mqttTypeCONNACK   byte = 2
	mqttTypePUBLISH   byte = 3
	mqttTypeSUBSCRIBE byte = 8
	mqttTypeSUBACK    byte = 9
)

func newSelfSignedTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject: pkix.Name{
			CommonName: "iotbci-netbench-mqtt",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
}
