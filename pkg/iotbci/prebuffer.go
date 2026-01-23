package iotbci

import (
	"bytes"
	"io"
	"net"
	"time"
)

// PreBufferedConn replays preRead bytes before reading from the underlying connection.
type PreBufferedConn struct {
	net.Conn
	buf []byte
}

func NewPreBufferedConn(conn net.Conn, preRead []byte) net.Conn {
	if len(preRead) == 0 {
		return conn
	}
	cp := make([]byte, len(preRead))
	copy(cp, preRead)
	return &PreBufferedConn{Conn: conn, buf: cp}
}

func (p *PreBufferedConn) Read(b []byte) (int, error) {
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}

func (p *PreBufferedConn) CloseWrite() error {
	if p == nil || p.Conn == nil {
		return nil
	}
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (p *PreBufferedConn) CloseRead() error {
	if p == nil || p.Conn == nil {
		return nil
	}
	if cr, ok := p.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// readOnlyConn is used for probing. It is a net.Conn wrapper over a bytes.Reader.
type readOnlyConn struct {
	*bytes.Reader
}

func (c *readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *readOnlyConn) Close() error                     { return nil }
func (c *readOnlyConn) LocalAddr() net.Addr              { return nil }
func (c *readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (c *readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c *readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *readOnlyConn) SetWriteDeadline(time.Time) error { return nil }
