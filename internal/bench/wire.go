package bench

import (
	"math"
	"net"
	"sync/atomic"
	"time"
)

type WireStats struct {
	BytesWritten atomic.Int64
	BytesRead    atomic.Int64
	WriteCalls   atomic.Int64
	ReadCalls    atomic.Int64

	// ByteFreq counts bytes written on the wire (per direction).
	ByteFreq [256]atomic.Uint64

	// WriteSizeBins is a log2 histogram of write sizes (0..31).
	WriteSizeBins [32]atomic.Uint64

	FirstWriteUnixNano atomic.Int64
	LastWriteUnixNano  atomic.Int64
}

func (s *WireStats) SnapshotWrittenFreq() [256]uint64 {
	var out [256]uint64
	if s == nil {
		return out
	}
	for i := 0; i < 256; i++ {
		out[i] = s.ByteFreq[i].Load()
	}
	return out
}

func (s *WireStats) recordWrite(p []byte) {
	if len(p) == 0 {
		return
	}
	s.BytesWritten.Add(int64(len(p)))
	s.WriteCalls.Add(1)

	now := time.Now().UnixNano()
	if s.FirstWriteUnixNano.Load() == 0 {
		s.FirstWriteUnixNano.CompareAndSwap(0, now)
	}
	s.LastWriteUnixNano.Store(now)

	for _, b := range p {
		s.ByteFreq[b].Add(1)
	}

	bin := log2Bin(len(p))
	s.WriteSizeBins[bin].Add(1)
}

func (s *WireStats) recordRead(n int) {
	if n <= 0 {
		return
	}
	s.BytesRead.Add(int64(n))
	s.ReadCalls.Add(1)
}

func log2Bin(n int) int {
	if n <= 0 {
		return 0
	}
	b := int(math.Log2(float64(n)))
	if b < 0 {
		return 0
	}
	if b >= 31 {
		return 31
	}
	return b
}

type CountingConn struct {
	net.Conn
	stats *WireStats
}

func WrapConn(c net.Conn, stats *WireStats) net.Conn {
	if stats == nil {
		stats = &WireStats{}
	}
	return &CountingConn{Conn: c, stats: stats}
}

func (c *CountingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.stats.recordWrite(p[:n])
	}
	return n, err
}

func (c *CountingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.stats.recordRead(n)
	}
	return n, err
}

func (c *CountingConn) Stats() *WireStats { return c.stats }

type CountingPacketConn struct {
	net.PacketConn
	stats *WireStats
}

func WrapPacketConn(pc net.PacketConn, stats *WireStats) net.PacketConn {
	if stats == nil {
		stats = &WireStats{}
	}
	return &CountingPacketConn{PacketConn: pc, stats: stats}
}

func (c *CountingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.stats.recordWrite(p[:n])
	}
	return n, err
}

func (c *CountingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.stats.recordRead(n)
	}
	return n, addr, err
}

func (c *CountingPacketConn) Stats() *WireStats { return c.stats }
