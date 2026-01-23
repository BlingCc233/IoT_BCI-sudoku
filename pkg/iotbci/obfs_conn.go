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
	uplinkSudoku := sudoku.NewConn(raw, table, obfs.PaddingMin, obfs.PaddingMax, false)
	if obfs.EnablePureDownlink {
		return uplinkSudoku
	}
	downlinkPacked := sudoku.NewPackedConn(raw, table, obfs.PaddingMin, obfs.PaddingMax)
	// Reader = downlinkPacked (server->client), Writer = uplinkSudoku (client->server).
	return newDirectionalConn(raw, downlinkPacked, uplinkSudoku)
}

func buildObfsConnForServer(raw net.Conn, table *sudoku.Table, obfs ObfsOptions, record bool) (*sudoku.Conn, net.Conn) {
	uplinkSudoku := sudoku.NewConn(raw, table, obfs.PaddingMin, obfs.PaddingMax, record)
	if obfs.EnablePureDownlink {
		return uplinkSudoku, uplinkSudoku
	}
	downlinkPacked := sudoku.NewPackedConn(raw, table, obfs.PaddingMin, obfs.PaddingMax)
	// Reader = uplinkSudoku (client->server), Writer = downlinkPacked (server->client).
	return uplinkSudoku, newDirectionalConn(raw, uplinkSudoku, downlinkPacked, downlinkPacked.Flush)
}
