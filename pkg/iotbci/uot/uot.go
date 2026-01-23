package uot

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// MagicByte marks a UDP-over-TCP session.
	MagicByte byte = 0xEE
	version   byte = 0x01

	maxFrame = 64 * 1024
)

func WritePreface(w io.Writer) error {
	_, err := w.Write([]byte{MagicByte, version})
	return err
}

func ReadPreface(r io.Reader) error {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] != MagicByte {
		return fmt.Errorf("invalid uot magic: %d", b[0])
	}
	if b[1] != version {
		return fmt.Errorf("unsupported uot version: %d", b[1])
	}
	return nil
}

func WriteDatagram(w io.Writer, addr string, payload []byte) error {
	addrBytes := []byte(addr)
	if len(addrBytes) > int(^uint16(0)) {
		return fmt.Errorf("address too long: %d", len(addrBytes))
	}
	if len(payload) > int(^uint16(0)) {
		return fmt.Errorf("payload too large: %d", len(payload))
	}
	if len(addrBytes) > maxFrame || len(payload) > maxFrame {
		return fmt.Errorf("frame too large")
	}

	var header [4]byte
	binary.BigEndian.PutUint16(header[0:2], uint16(len(addrBytes)))
	binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	if err := writeFull(w, addrBytes); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func ReadDatagram(r io.Reader) (string, []byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", nil, err
	}
	addrLen := int(binary.BigEndian.Uint16(header[0:2]))
	payloadLen := int(binary.BigEndian.Uint16(header[2:4]))
	if addrLen < 0 || addrLen > maxFrame {
		return "", nil, fmt.Errorf("invalid address length: %d", addrLen)
	}
	if payloadLen < 0 || payloadLen > maxFrame {
		return "", nil, fmt.Errorf("invalid payload length: %d", payloadLen)
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return "", nil, err
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", nil, err
	}
	return string(addrBuf), payload, nil
}

type Addr string

func (a Addr) Network() string { return "uot" }
func (a Addr) String() string  { return string(a) }

// PacketConn implements net.PacketConn over a stream net.Conn using UoT framing.
type PacketConn struct {
	conn    net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func NewPacketConn(conn net.Conn) *PacketConn {
	return &PacketConn{conn: conn}
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var header [4]byte
	if _, err := io.ReadFull(c.conn, header[:]); err != nil {
		return 0, nil, err
	}
	addrLen := int(binary.BigEndian.Uint16(header[0:2]))
	payloadLen := int(binary.BigEndian.Uint16(header[2:4]))
	if addrLen < 0 || addrLen > maxFrame {
		return 0, nil, fmt.Errorf("invalid address length: %d", addrLen)
	}
	if payloadLen < 0 || payloadLen > maxFrame {
		return 0, nil, fmt.Errorf("invalid payload length: %d", payloadLen)
	}

	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(c.conn, addrBuf); err != nil {
		return 0, nil, err
	}

	if payloadLen <= len(p) {
		if _, err := io.ReadFull(c.conn, p[:payloadLen]); err != nil {
			return 0, nil, err
		}
		return payloadLen, Addr(string(addrBuf)), nil
	}

	// Short buffer: read what we can, then discard the rest to keep framing aligned.
	if len(p) > 0 {
		if _, err := io.ReadFull(c.conn, p); err != nil {
			return 0, nil, err
		}
	}
	remain := payloadLen - len(p)
	if remain > 0 {
		if _, err := io.CopyN(io.Discard, c.conn, int64(remain)); err != nil {
			return 0, nil, err
		}
	}
	return len(p), Addr(string(addrBuf)), io.ErrShortBuffer
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	dst := ""
	if addr != nil {
		dst = addr.String()
	}
	if err := WriteDatagram(c.conn, dst, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *PacketConn) Close() error { return c.conn.Close() }

func (c *PacketConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *PacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *PacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
