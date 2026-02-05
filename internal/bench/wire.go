package bench

import (
	"math/bits"
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

	// WriteInterArrivalMsBins is a log2 histogram of inter-arrival times between write calls (0..31).
	WriteInterArrivalMsBins [32]atomic.Uint64

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

func (s *WireStats) SnapshotWriteSizeBins() [32]uint64 {
	var out [32]uint64
	if s == nil {
		return out
	}
	for i := 0; i < 32; i++ {
		out[i] = s.WriteSizeBins[i].Load()
	}
	return out
}

func (s *WireStats) SnapshotWriteInterArrivalMsBins() [32]uint64 {
	var out [32]uint64
	if s == nil {
		return out
	}
	for i := 0; i < 32; i++ {
		out[i] = s.WriteInterArrivalMsBins[i].Load()
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
	prev := s.LastWriteUnixNano.Swap(now)
	if prev != 0 {
		delta := now - prev
		if delta < 0 {
			delta = -delta
		}
		ms := uint64(delta) / uint64(time.Millisecond)
		bin := bits.Len64(ms+1) - 1
		if bin > 31 {
			bin = 31
		}
		s.WriteInterArrivalMsBins[bin].Add(1)
	}

	// Byte frequency: keep small writes fast (common in MQTT/TLS), but avoid per-byte atomics
	// for large writes (common in Sudoku due to wire expansion).
	if len(p) <= 512 {
		for _, b := range p {
			s.ByteFreq[b].Add(1)
		}
	} else {
		var counts [256]uint32
		var seen [256]byte
		seenN := 0
		for _, b := range p {
			if counts[b] == 0 {
				seen[seenN] = b
				seenN++
			}
			counts[b]++
		}
		for i := 0; i < seenN; i++ {
			b := seen[i]
			s.ByteFreq[b].Add(uint64(counts[b]))
		}
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
	if n >= 1<<31 {
		return 31
	}
	return bits.Len(uint(n)) - 1
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
