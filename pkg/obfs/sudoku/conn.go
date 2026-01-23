package sudoku

import (
	"bufio"
	"bytes"
	crypto_rand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
)

const IOBufferSize = 32 * 1024

var perm4 = [24][4]byte{
	{0, 1, 2, 3},
	{0, 1, 3, 2},
	{0, 2, 1, 3},
	{0, 2, 3, 1},
	{0, 3, 1, 2},
	{0, 3, 2, 1},
	{1, 0, 2, 3},
	{1, 0, 3, 2},
	{1, 2, 0, 3},
	{1, 2, 3, 0},
	{1, 3, 0, 2},
	{1, 3, 2, 0},
	{2, 0, 1, 3},
	{2, 0, 3, 1},
	{2, 1, 0, 3},
	{2, 1, 3, 0},
	{2, 3, 0, 1},
	{2, 3, 1, 0},
	{3, 0, 1, 2},
	{3, 0, 2, 1},
	{3, 1, 0, 2},
	{3, 1, 2, 0},
	{3, 2, 0, 1},
	{3, 2, 1, 0},
}

type Conn struct {
	net.Conn
	table  *Table
	reader *bufio.Reader

	recorder   *bytes.Buffer
	recording  bool
	recordLock sync.Mutex

	rawBuf      []byte
	pendingData []byte
	hintBuf     []byte

	rng         *rand.Rand
	paddingRate float32
}

func NewConn(c net.Conn, table *Table, paddingMinPct, paddingMaxPct int, record bool) *Conn {
	var seedBytes [8]byte
	if _, err := crypto_rand.Read(seedBytes[:]); err != nil {
		binary.BigEndian.PutUint64(seedBytes[:], uint64(rand.Int63()))
	}
	seed := int64(binary.BigEndian.Uint64(seedBytes[:]))
	localRng := rand.New(rand.NewSource(seed))

	min := float32(paddingMinPct) / 100.0
	rngRange := float32(paddingMaxPct-paddingMinPct) / 100.0
	rate := min + localRng.Float32()*rngRange

	sc := &Conn{
		Conn:        c,
		table:       table,
		reader:      bufio.NewReaderSize(c, IOBufferSize),
		rawBuf:      make([]byte, IOBufferSize),
		pendingData: make([]byte, 0, 4096),
		hintBuf:     make([]byte, 0, 4),
		rng:         localRng,
		paddingRate: rate,
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

	out := make([]byte, 0, len(p)*6)
	pads := sc.table.PaddingPool
	padLen := len(pads)

	for _, b := range p {
		if sc.rng.Float32() < sc.paddingRate {
			out = append(out, pads[sc.rng.Intn(padLen)])
		}

		puzzles := sc.table.EncodeTable[b]
		puzzle := puzzles[sc.rng.Intn(len(puzzles))]
		perm := perm4[sc.rng.Intn(len(perm4))]

		for _, idx := range perm {
			if sc.rng.Float32() < sc.paddingRate {
				out = append(out, pads[sc.rng.Intn(padLen)])
			}
			out = append(out, puzzle[idx])
		}
	}

	if sc.rng.Float32() < sc.paddingRate {
		out = append(out, pads[sc.rng.Intn(padLen)])
	}

	_, err := sc.Conn.Write(out)
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

	for {
		if len(sc.pendingData) > 0 {
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

			for _, b := range chunk {
				if !sc.table.layout.isHint(b) {
					continue
				}

				sc.hintBuf = append(sc.hintBuf, b)
				if len(sc.hintBuf) == 4 {
					key := packHintsToKey([4]byte{sc.hintBuf[0], sc.hintBuf[1], sc.hintBuf[2], sc.hintBuf[3]})
					val, ok := sc.table.DecodeMap[key]
					if !ok {
						return 0, ErrInvalidSudokuMapMiss
					}
					sc.pendingData = append(sc.pendingData, val)
					sc.hintBuf = sc.hintBuf[:0]
				}
			}
		}
		if rErr != nil {
			if errors.Is(rErr, net.ErrClosed) && len(sc.pendingData) > 0 {
				break
			}
			return 0, rErr
		}
		if len(sc.pendingData) > 0 {
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
