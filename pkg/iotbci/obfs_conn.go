package iotbci

import (
	"io"
	"net"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/obfs/sudoku"
)

const (
	DownlinkModePure   byte = 0x01
	DownlinkModePacked byte = 0x02
)

type obfsUplinkConn interface {
	net.Conn
	StopRecording()
	GetBufferedAndRecorded() []byte
}

type directionalConn struct {
	net.Conn
	reader  io.Reader
	writer  io.Writer
	closers []func() error
}

func newDirectionalConn(base net.Conn, reader io.Reader, writer io.Writer, closers ...func() error) net.Conn {
	return &directionalConn{
		Conn:    base,
		reader:  reader,
		writer:  writer,
		closers: closers,
	}
}

func (c *directionalConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *directionalConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *directionalConn) CloseWrite() error {
	var firstErr error
	for _, fn := range c.closers {
		if fn == nil {
			continue
		}
		if err := fn(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if cw, ok := c.writer.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && firstErr == nil {
			firstErr = err
		}
		return firstErr
	}
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *directionalConn) CloseRead() error {
	if cr, ok := c.reader.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *directionalConn) Close() error {
	var firstErr error
	for _, fn := range c.closers {
		if fn == nil {
			continue
		}
		if err := fn(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := c.Conn.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func downlinkModeByte(enablePure bool) byte {
	if enablePure {
		return DownlinkModePure
	}
	return DownlinkModePacked
}

func buildObfsConnForClient(raw net.Conn, table *sudoku.Table, obfs ObfsOptions) net.Conn {
	// Fast path: full packed is symmetrical, one wrapper is enough.
	if obfs.EnablePackedUplink && !obfs.EnablePureDownlink {
		return sudoku.NewPackedConn(raw, table, obfs.PaddingMin, obfs.PaddingMax)
	}

	var uplink io.Writer
	if obfs.EnablePackedUplink {
		uplink = sudoku.NewPackedConn(raw, table, obfs.PaddingMin, obfs.PaddingMax)
	} else {
		uplink = sudoku.NewConn(raw, table, obfs.PaddingMin, obfs.PaddingMax, false)
	}

	if obfs.EnablePureDownlink {
		if !obfs.EnablePackedUplink {
			// Symmetric pure mode.
			return uplink.(net.Conn)
		}
		// Reader = pure sudoku (server->client), Writer = packed (client->server).
		downlinkPure := sudoku.NewConn(raw, table, obfs.PaddingMin, obfs.PaddingMax, false)
		return newDirectionalConn(raw, downlinkPure, uplink)
	}

	// Reader = packed (server->client), Writer = pure sudoku OR packed uplink.
	downlinkPacked := sudoku.NewPackedConn(raw, table, obfs.PaddingMin, obfs.PaddingMax)
	return newDirectionalConn(raw, downlinkPacked, uplink)
}

func buildObfsConnForServer(raw net.Conn, table *sudoku.Table, obfs ObfsOptions, record bool) (obfsUplinkConn, net.Conn) {
	var uplink obfsUplinkConn
	if obfs.EnablePackedUplink {
		uplink = sudoku.NewPackedConnWithRecord(raw, table, obfs.PaddingMin, obfs.PaddingMax, record)
	} else {
		uplink = sudoku.NewConn(raw, table, obfs.PaddingMin, obfs.PaddingMax, record)
	}

	// Full packed is symmetrical: reuse one wrapper for both directions.
	if obfs.EnablePackedUplink && !obfs.EnablePureDownlink {
		return uplink, uplink
	}

	if obfs.EnablePureDownlink {
		if !obfs.EnablePackedUplink {
			// Symmetric pure mode.
			return uplink, uplink
		}
		// Reader = packed uplink (client->server), Writer = pure sudoku (server->client).
		downlinkPure := sudoku.NewConn(raw, table, obfs.PaddingMin, obfs.PaddingMax, false)
		return uplink, newDirectionalConn(raw, uplink, downlinkPure)
	}

	// Reader = pure sudoku OR packed uplink (client->server), Writer = packed (server->client).
	downlinkPacked := sudoku.NewPackedConn(raw, table, obfs.PaddingMin, obfs.PaddingMax)
	return uplink, newDirectionalConn(raw, uplink, downlinkPacked)
}
