package sudoku

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"sync"
)

const IOBufferSize = 32 * 1024

type Conn struct {
	net.Conn
	table  *Table
	reader *bufio.Reader

	recorder   *bytes.Buffer
	recording  bool
	recordLock sync.Mutex

	rawBuf      []byte
	pendingData []byte
	hintBuf     [4]byte
	hintCount   int

	rng          fastRNG
	paddingRate  float32
	padThreshold uint32
	padPool      []byte
	padLen       int

	writeMu  sync.Mutex
	writeBuf []byte
}

func NewConn(c net.Conn, table *Table, paddingMinPct, paddingMaxPct int, record bool) *Conn {
	localRng := newFastRNG()

	min := float32(paddingMinPct) / 100.0
	rngRange := float32(paddingMaxPct-paddingMinPct) / 100.0
	rate := min + localRng.Float32()*rngRange
	threshold := func() uint32 {
		if rate <= 0 {
			return 0
		}
		if rate >= 1 {
			return ^uint32(0)
		}
		return uint32(float64(rate) * 4294967295.0)
	}()

	sc := &Conn{
		Conn:         c,
		table:        table,
		reader:       bufio.NewReaderSize(c, IOBufferSize),
		rawBuf:       make([]byte, IOBufferSize),
		pendingData:  make([]byte, 0, IOBufferSize/4),
		rng:          localRng,
		paddingRate:  rate,
		padThreshold: threshold,
		padPool:      table.PaddingPool,
		padLen:       len(table.PaddingPool),
		writeBuf:     make([]byte, 0, 4096),
	}
	if record {
		sc.recorder = new(bytes.Buffer)
		sc.recording = true
	}
	return sc
}

func (sc *Conn) CloseWrite() error {
	if sc == nil || sc.Conn == nil {
		return nil
	}
	if cw, ok := sc.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (sc *Conn) CloseRead() error {
	if sc == nil || sc.Conn == nil {
		return nil
	}
	if cr, ok := sc.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (sc *Conn) StopRecording() {
	sc.recordLock.Lock()
	sc.recording = false
	sc.recorder = nil
	sc.recordLock.Unlock()
}

func (sc *Conn) GetBufferedAndRecorded() []byte {
	if sc == nil {
		return nil
	}

	sc.recordLock.Lock()
	defer sc.recordLock.Unlock()

	var recorded []byte
	if sc.recorder != nil {
		recorded = sc.recorder.Bytes()
	}

	buffered := sc.reader.Buffered()
	if buffered <= 0 {
		return recorded
	}
	peeked, _ := sc.reader.Peek(buffered)
	full := make([]byte, 0, len(recorded)+len(peeked))
	full = append(full, recorded...)
	full = append(full, peeked...)
	return full
}

func (sc *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()

	pads := sc.padPool
	padLen := sc.padLen
	rng := &sc.rng
	padThreshold := sc.padThreshold
	encodeTable := &sc.table.EncodeTable
	hasPadding := padThreshold != 0 && padLen > 0

	needed := len(p)*4 + 16
	if hasPadding {
		needed = len(p)*6 + 16
	}
	if cap(sc.writeBuf) < needed {
		sc.writeBuf = make([]byte, 0, needed)
	}
	out := sc.writeBuf[:0]

	if !hasPadding {
		outLen := len(p) * 4
		out = sc.writeBuf[:outLen]
		oi := 0
		puzzleIdx := rng.Uint32() & 7
		for _, b := range p {
			puzzles := (*encodeTable)[b]
			puzzle := puzzles[int(puzzleIdx)]
			puzzleIdx = (puzzleIdx + 1) & 7
			out[oi] = puzzle[0]
			out[oi+1] = puzzle[1]
			out[oi+2] = puzzle[2]
			out[oi+3] = puzzle[3]
			oi += 4
		}
		_, err := sc.Conn.Write(out)
		sc.writeBuf = out[:0]
		return len(p), err
	}

	for _, b := range p {
		if rng.Uint32() <= padThreshold {
			out = append(out, pads[int(uint64(rng.Uint32())*uint64(padLen)>>32)])
		}

		puzzles := (*encodeTable)[b]
		puzzle := puzzles[int(rng.Uint32()&7)]

		if rng.Uint32() <= padThreshold {
			out = append(out, pads[int(uint64(rng.Uint32())*uint64(padLen)>>32)])
		}
		out = append(out, puzzle[0])
		if rng.Uint32() <= padThreshold {
			out = append(out, pads[int(uint64(rng.Uint32())*uint64(padLen)>>32)])
		}
		out = append(out, puzzle[1])
		if rng.Uint32() <= padThreshold {
			out = append(out, pads[int(uint64(rng.Uint32())*uint64(padLen)>>32)])
		}
		out = append(out, puzzle[2])
		if rng.Uint32() <= padThreshold {
			out = append(out, pads[int(uint64(rng.Uint32())*uint64(padLen)>>32)])
		}
		out = append(out, puzzle[3])
	}

	if rng.Uint32() <= padThreshold {
		out = append(out, pads[int(uint64(rng.Uint32())*uint64(padLen)>>32)])
	}

	_, err := sc.Conn.Write(out)
	sc.writeBuf = out[:0]
	return len(p), err
}

func (sc *Conn) Read(p []byte) (int, error) {
	if len(sc.pendingData) > 0 {
		n := copy(p, sc.pendingData)
		if n == len(sc.pendingData) {
			sc.pendingData = sc.pendingData[:0]
		} else {
			sc.pendingData = sc.pendingData[n:]
		}
		return n, nil
	}

	hasPadding := sc.padThreshold != 0 && sc.padLen > 0

	for {
		if len(sc.pendingData) >= len(p) {
			break
		}

		nr, rErr := sc.reader.Read(sc.rawBuf)
		if nr > 0 {
			chunk := sc.rawBuf[:nr]
			sc.recordLock.Lock()
			if sc.recording {
				sc.recorder.Write(chunk)
			}
			sc.recordLock.Unlock()

			if !hasPadding {
				// Fast path: in no-padding mode, every wire byte is a hint and every 4 hints decode to 1 byte.
				need := (nr+sc.hintCount)/4 + 16
				if cap(sc.pendingData)-len(sc.pendingData) < need {
					newCap := len(sc.pendingData) + need
					buf := make([]byte, len(sc.pendingData), newCap)
					copy(buf, sc.pendingData)
					sc.pendingData = buf
				}

				i := 0
				if sc.hintCount != 0 {
					for sc.hintCount < 4 && i < len(chunk) {
						sc.hintBuf[sc.hintCount] = chunk[i]
						sc.hintCount++
						i++
					}
					if sc.hintCount == 4 {
						key := uint32(sc.hintBuf[0])<<24 | uint32(sc.hintBuf[1])<<16 | uint32(sc.hintBuf[2])<<8 | uint32(sc.hintBuf[3])
						val, ok := sc.table.Decode(key)
						if !ok {
							return 0, ErrInvalidSudokuMapMiss
						}
						sc.pendingData = append(sc.pendingData, val)
						sc.hintCount = 0
					}
				}

				rem := chunk[i:]
				full := len(rem) &^ 3
				decoded := full / 4
				if decoded > 0 {
					start := len(sc.pendingData)
					sc.pendingData = sc.pendingData[:start+decoded]
					di := start
					for j := 0; j < full; j += 4 {
						key := uint32(rem[j])<<24 | uint32(rem[j+1])<<16 | uint32(rem[j+2])<<8 | uint32(rem[j+3])
						val, ok := sc.table.Decode(key)
						if !ok {
							return 0, ErrInvalidSudokuMapMiss
						}
						sc.pendingData[di] = val
						di++
					}
				}

				tail := rem[full:]
				copy(sc.hintBuf[:], tail)
				sc.hintCount = len(tail)
			} else {
				// Conservative: worst-case all bytes are hints -> 4 hints per decoded byte.
				if cap(sc.pendingData)-len(sc.pendingData) < (nr/4)+16 {
					newCap := len(sc.pendingData) + (nr / 4) + 16
					buf := make([]byte, len(sc.pendingData), newCap)
					copy(buf, sc.pendingData)
					sc.pendingData = buf
				}

				layout := sc.table.layout
				for _, b := range chunk {
					if !layout.isHint(b) {
						continue
					}

					sc.hintBuf[sc.hintCount] = b
					sc.hintCount++
					if sc.hintCount == 4 {
						key := uint32(sc.hintBuf[0])<<24 | uint32(sc.hintBuf[1])<<16 | uint32(sc.hintBuf[2])<<8 | uint32(sc.hintBuf[3])
						val, ok := sc.table.Decode(key)
						if !ok {
							return 0, ErrInvalidSudokuMapMiss
						}
						sc.pendingData = append(sc.pendingData, val)
						sc.hintCount = 0
					}
				}
			}
		}
		if rErr != nil {
			if errors.Is(rErr, net.ErrClosed) && len(sc.pendingData) > 0 {
				break
			}
			return 0, rErr
		}
		if len(sc.pendingData) >= len(p) {
			break
		}
	}

	n := copy(p, sc.pendingData)
	if n == len(sc.pendingData) {
		sc.pendingData = sc.pendingData[:0]
	} else {
		sc.pendingData = sc.pendingData[n:]
	}
	return n, nil
}
