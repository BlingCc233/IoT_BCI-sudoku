package sudoku

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"sync"
)

// PackedConn packs plaintext into 6-bit groups on the write path, which improves downlink
// bandwidth utilization when ciphertext is already high-entropy (AEAD recommended).
type PackedConn struct {
	net.Conn
	table  *Table
	reader *bufio.Reader

	recorder   *bytes.Buffer
	recording  bool
	recordLock sync.Mutex

	rawBuf      []byte
	pendingData []byte

	writeMu  sync.Mutex
	writeBuf []byte
	bitBuf   uint64
	bitCount int

	readBitBuf uint64
	readBits   int

	rng          fastRNG
	paddingRate  float32
	padThreshold uint32
	padMarker    byte
	padPool      []byte
}

func NewPackedConn(c net.Conn, table *Table, paddingMinPct, paddingMaxPct int) *PackedConn {
	return NewPackedConnWithRecord(c, table, paddingMinPct, paddingMaxPct, false)
}

func NewPackedConnWithRecord(c net.Conn, table *Table, paddingMinPct, paddingMaxPct int, record bool) *PackedConn {
	localRng := newFastRNG()

	min := float32(paddingMinPct) / 100.0
	rngRange := float32(paddingMaxPct-paddingMinPct) / 100.0
	rate := min + localRng.Float32()*rngRange

	pc := &PackedConn{
		Conn:        c,
		table:       table,
		reader:      bufio.NewReaderSize(c, IOBufferSize),
		rawBuf:      make([]byte, IOBufferSize),
		pendingData: make([]byte, 0, 4096),
		writeBuf:    make([]byte, 0, 4096),
		rng:         localRng,
		paddingRate: rate,
		padThreshold: func() uint32 {
			if rate <= 0 {
				return 0
			}
			if rate >= 1 {
				return ^uint32(0)
			}
			return uint32(float64(rate) * 4294967295.0)
		}(),
	}
	if record {
		pc.recorder = new(bytes.Buffer)
		pc.recording = true
	}

	pc.padMarker = table.layout.padMarker
	for _, b := range table.PaddingPool {
		if b != pc.padMarker {
			pc.padPool = append(pc.padPool, b)
		}
	}
	if len(pc.padPool) == 0 {
		pc.padPool = append(pc.padPool, pc.padMarker)
	}
	return pc
}

func (pc *PackedConn) CloseWrite() error {
	if pc == nil || pc.Conn == nil {
		return nil
	}
	var firstErr error
	if err := pc.Flush(); err != nil && firstErr == nil {
		firstErr = err
	}
	if cw, ok := pc.Conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (pc *PackedConn) CloseRead() error {
	if pc == nil || pc.Conn == nil {
		return nil
	}
	if cr, ok := pc.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (pc *PackedConn) StopRecording() {
	pc.recordLock.Lock()
	pc.recording = false
	pc.recorder = nil
	pc.recordLock.Unlock()
}

func (pc *PackedConn) GetBufferedAndRecorded() []byte {
	if pc == nil {
		return nil
	}

	pc.recordLock.Lock()
	defer pc.recordLock.Unlock()

	var recorded []byte
	if pc.recorder != nil {
		recorded = pc.recorder.Bytes()
	}

	buffered := pc.reader.Buffered()
	if buffered <= 0 {
		return recorded
	}
	peeked, _ := pc.reader.Peek(buffered)
	full := make([]byte, 0, len(recorded)+len(peeked))
	full = append(full, recorded...)
	full = append(full, peeked...)
	return full
}

func (pc *PackedConn) getPaddingByte() byte {
	return pc.padPool[pc.fastIndex(len(pc.padPool))]
}

func (pc *PackedConn) maybeAddPadding(out []byte) []byte {
	if pc.padThreshold != 0 && pc.rng.Uint32() <= pc.padThreshold {
		out = append(out, pc.getPaddingByte())
	}
	return out
}

func (pc *PackedConn) fastIndex(n int) int {
	return int(uint64(pc.rng.Uint32()) * uint64(n) >> 32)
}

func (pc *PackedConn) encodeGroup(group6b byte) byte {
	return pc.table.layout.encodeGroup(group6b)
}

func (pc *PackedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	needed := len(p)*3/2 + 32
	if cap(pc.writeBuf) < needed {
		pc.writeBuf = make([]byte, 0, needed)
	}
	out := pc.writeBuf[:0]
	hasPadding := pc.padThreshold != 0

	i := 0
	n := len(p)

	// Align any pending bits.
	for pc.bitCount > 0 && i < n {
		if hasPadding && pc.rng.Uint32() <= pc.padThreshold {
			out = append(out, pc.getPaddingByte())
		}
		b := p[i]
		i++
		pc.bitBuf = (pc.bitBuf << 8) | uint64(b)
		pc.bitCount += 8
		for pc.bitCount >= 6 {
			pc.bitCount -= 6
			group := byte(pc.bitBuf >> pc.bitCount)
			if pc.bitCount == 0 {
				pc.bitBuf = 0
			} else {
				pc.bitBuf &= (1 << pc.bitCount) - 1
			}
			if hasPadding && pc.rng.Uint32() <= pc.padThreshold {
				out = append(out, pc.getPaddingByte())
			}
			out = append(out, pc.encodeGroup(group&0x3F))
		}
	}

	// Fast path: 3 bytes -> 4 groups.
	for i+2 < n {
		b1, b2, b3 := p[i], p[i+1], p[i+2]
		i += 3

		g1 := (b1 >> 2) & 0x3F
		g2 := ((b1 & 0x03) << 4) | ((b2 >> 4) & 0x0F)
		g3 := ((b2 & 0x0F) << 2) | ((b3 >> 6) & 0x03)
		g4 := b3 & 0x3F

		if hasPadding && pc.rng.Uint32() <= pc.padThreshold {
			out = append(out, pc.getPaddingByte())
		}
		out = append(out, pc.encodeGroup(g1))
		if hasPadding && pc.rng.Uint32() <= pc.padThreshold {
			out = append(out, pc.getPaddingByte())
		}
		out = append(out, pc.encodeGroup(g2))
		if hasPadding && pc.rng.Uint32() <= pc.padThreshold {
			out = append(out, pc.getPaddingByte())
		}
		out = append(out, pc.encodeGroup(g3))
		if hasPadding && pc.rng.Uint32() <= pc.padThreshold {
			out = append(out, pc.getPaddingByte())
		}
		out = append(out, pc.encodeGroup(g4))
	}

	// Tail bytes.
	for ; i < n; i++ {
		b := p[i]
		pc.bitBuf = (pc.bitBuf << 8) | uint64(b)
		pc.bitCount += 8
		for pc.bitCount >= 6 {
			pc.bitCount -= 6
			group := byte(pc.bitBuf >> pc.bitCount)
			if pc.bitCount == 0 {
				pc.bitBuf = 0
			} else {
				pc.bitBuf &= (1 << pc.bitCount) - 1
			}
			if hasPadding && pc.rng.Uint32() <= pc.padThreshold {
				out = append(out, pc.getPaddingByte())
			}
			out = append(out, pc.encodeGroup(group&0x3F))
		}
	}

	// Residual bits: emit one group + pad marker.
	if pc.bitCount > 0 {
		if hasPadding && pc.rng.Uint32() <= pc.padThreshold {
			out = append(out, pc.getPaddingByte())
		}
		group := byte(pc.bitBuf << (6 - pc.bitCount))
		pc.bitBuf = 0
		pc.bitCount = 0
		out = append(out, pc.encodeGroup(group&0x3F))
		out = append(out, pc.padMarker)
	}

	if len(out) > 0 {
		_, err := pc.Conn.Write(out)
		pc.writeBuf = out[:0]
		return len(p), err
	}
	pc.writeBuf = out[:0]
	return len(p), nil
}

func (pc *PackedConn) Flush() error {
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	out := pc.writeBuf[:0]
	if pc.bitCount > 0 {
		group := byte(pc.bitBuf << (6 - pc.bitCount))
		pc.bitBuf = 0
		pc.bitCount = 0

		out = append(out, pc.encodeGroup(group&0x3F))
		out = append(out, pc.padMarker)
	}

	if len(out) > 0 {
		_, err := pc.Conn.Write(out)
		pc.writeBuf = out[:0]
		return err
	}
	return nil
}

func (pc *PackedConn) Read(p []byte) (int, error) {
	if len(pc.pendingData) > 0 {
		n := copy(p, pc.pendingData)
		if n == len(pc.pendingData) {
			pc.pendingData = pc.pendingData[:0]
		} else {
			pc.pendingData = pc.pendingData[n:]
		}
		return n, nil
	}

	for {
		nr, rErr := pc.reader.Read(pc.rawBuf)
		if nr > 0 {
			chunk := pc.rawBuf[:nr]
			pc.recordLock.Lock()
			if pc.recording {
				pc.recorder.Write(chunk)
			}
			pc.recordLock.Unlock()

			rBuf := pc.readBitBuf
			rBits := pc.readBits
			padMarker := pc.padMarker
			layout := pc.table.layout

			// Worst case: all bytes are hint groups => 6 bits each => ~3/4 bytes decoded.
			need := (nr*3)/4 + 16
			if cap(pc.pendingData)-len(pc.pendingData) < need {
				newCap := len(pc.pendingData) + need
				buf := make([]byte, len(pc.pendingData), newCap)
				copy(buf, pc.pendingData)
				pc.pendingData = buf
			}

			for _, b := range chunk {
				if !layout.isHint(b) {
					if b == padMarker {
						rBuf = 0
						rBits = 0
					}
					continue
				}

				group, ok := layout.decodeGroup(b)
				if !ok {
					return 0, ErrInvalidSudokuMapMiss
				}

				rBuf = (rBuf << 6) | uint64(group)
				rBits += 6
				if rBits >= 8 {
					rBits -= 8
					val := byte(rBuf >> rBits)
					pc.pendingData = append(pc.pendingData, val)
				}
			}

			pc.readBitBuf = rBuf
			pc.readBits = rBits
		}

		if rErr != nil {
			if rErr == io.EOF {
				pc.readBitBuf = 0
				pc.readBits = 0
			}
			if len(pc.pendingData) > 0 {
				break
			}
			return 0, rErr
		}

		if len(pc.pendingData) >= len(p) {
			break
		}
	}

	n := copy(p, pc.pendingData)
	if n == len(pc.pendingData) {
		pc.pendingData = pc.pendingData[:0]
	} else {
		pc.pendingData = pc.pendingData[n:]
	}
	return n, nil
}
