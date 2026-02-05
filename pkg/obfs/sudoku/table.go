package sudoku

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"sync"
	"time"
)

var (
	ErrInvalidSudokuMapMiss = errors.New("sudoku: decode map miss")
)

const emptyDecodeKey uint32 = ^uint32(0)

type tableCacheEntry struct {
	once sync.Once
	t    *Table
	err  error
}

var (
	tableCache sync.Map // map[cacheKey]*tableCacheEntry

	comb4Once sync.Once
	comb4     [][4]uint8
)

type Table struct {
	EncodeTable [256][][4]byte
	decodeKeys  []uint32
	decodeVals  []byte
	decodeMask  uint32
	decodeLUT24 []uint16 // optional: 24-bit LUT (4*6bit) for fast decode (byte+1, 0=miss)
	hintTo6     [256]byte
	hintTo6OK   [256]bool
	PaddingPool []byte
	IsASCII     bool
	layout      *byteLayout
}

var (
	uniqueCombosOnce   sync.Once
	uniqueCombosByGrid [][]uint16
)

const maxPuzzlesPerByte = 8

// NewTable builds a table using a built-in layout (ASCII/entropy) with optional key-based rotation.
func NewTable(key string, mode string) (*Table, error) {
	return NewTableWithCustom(key, mode, "")
}

// NewTableWithCustom builds a table using either a built-in layout or a custom x/v/p pattern.
//
// ASCII always wins if requested. Custom patterns are ignored when ASCII is preferred.
func NewTableWithCustom(key string, mode string, customPattern string) (*Table, error) {
	start := time.Now()

	layout, err := resolveLayout(mode, customPattern)
	if err != nil {
		return nil, err
	}

	cacheKey := key + "\x00" + layout.name
	entryAny, _ := tableCache.LoadOrStore(cacheKey, &tableCacheEntry{})
	entry := entryAny.(*tableCacheEntry)
	entry.once.Do(func() {
		entry.t, entry.err = buildTableWithLayout(key, layout)
		if entry.err != nil {
			tableCache.Delete(cacheKey)
		}
	})
	if entry.err != nil {
		return nil, entry.err
	}
	t := entry.t

	_ = start // reserved for future: record init time in metrics/debug builds
	return t, nil
}

func comb4Ref() [][4]uint8 {
	comb4Once.Do(func() {
		// Precompute combinations of 4 positions out of 16.
		combinations := make([][4]uint8, 0, 1820)
		var comb [4]uint8
		var gen func(start, k, idx int)
		gen = func(start, k, idx int) {
			if k == 0 {
				combinations = append(combinations, comb)
				return
			}
			for i := start; i <= 16-k; i++ {
				comb[idx] = uint8(i)
				gen(i+1, k-1, idx+1)
			}
		}
		gen(0, 4, 0)
		comb4 = combinations
	})
	return comb4
}

func buildTableWithLayout(key string, layout *byteLayout) (*Table, error) {
	t := &Table{
		IsASCII: layout.name == "ascii",
		layout:  layout,
	}
	t.PaddingPool = append(t.PaddingPool, layout.paddingPool...)
	t.buildHintTo6()

	// Generate all grids and deterministically shuffle them with key.
	allGrids := allGridsRef()
	if len(allGrids) < 256 {
		return nil, errors.New("insufficient sudoku grids to cover 256 byte values")
	}
	h := sha256.Sum256([]byte(key))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	rng := rand.New(rand.NewSource(seed))

	gridIdxs := make([]int, len(allGrids))
	for i := range gridIdxs {
		gridIdxs[i] = i
	}
	rng.Shuffle(len(gridIdxs), func(i, j int) { gridIdxs[i], gridIdxs[j] = gridIdxs[j], gridIdxs[i] })

	combinations := comb4Ref()
	uniqueByGrid := uniqueCombosByGridRef()

	// Pre-size decode table for the selected grids.
	totalEntries := 0
	for byteVal := 0; byteVal < 256; byteVal++ {
		gi := gridIdxs[byteVal]
		if gi < 0 || gi >= len(uniqueByGrid) {
			continue
		}
		n := len(uniqueByGrid[gi])
		if n > maxPuzzlesPerByte {
			n = maxPuzzlesPerByte
		}
		totalEntries += n
	}
	if totalEntries <= 0 {
		totalEntries = 256
	}
	// Open-addressing table sized to keep load factor <= 0.5.
	tableSize := 1
	target := totalEntries * 2
	for tableSize < target {
		tableSize <<= 1
	}
	if tableSize < 512 {
		tableSize = 512
	}
	t.decodeKeys = make([]uint32, tableSize)
	for i := range t.decodeKeys {
		t.decodeKeys[i] = emptyDecodeKey
	}
	t.decodeVals = make([]byte, tableSize)
	t.decodeMask = uint32(tableSize - 1)

	seen := make(map[uint32]byte, totalEntries)

	// Build per-byte mapping.
	for byteVal := 0; byteVal < 256; byteVal++ {
		gridIdx := gridIdxs[byteVal]
		targetGrid := allGrids[gridIdx]

		comboIdxs := uniqueByGrid[gridIdx]
		if len(comboIdxs) > maxPuzzlesPerByte {
			comboIdxs = comboIdxs[:maxPuzzlesPerByte]
		}
		out := make([][4]byte, 0, len(comboIdxs))

		for _, comboIdx := range comboIdxs {
			positions := combinations[comboIdx]

			var encoded [4]byte
			for i, p := range positions {
				// pos: 0..15, val: 1..4 (stored as 0..3 in encoding).
				encoded[i] = t.layout.encodeHint(targetGrid[p]-1, p)
			}
			// Keep hints in ascending order so decoders can pack without per-byte sorting.
			if encoded[0] > encoded[1] {
				encoded[0], encoded[1] = encoded[1], encoded[0]
			}
			if encoded[2] > encoded[3] {
				encoded[2], encoded[3] = encoded[3], encoded[2]
			}
			if encoded[0] > encoded[2] {
				encoded[0], encoded[2] = encoded[2], encoded[0]
			}
			if encoded[1] > encoded[3] {
				encoded[1], encoded[3] = encoded[3], encoded[1]
			}
			if encoded[1] > encoded[2] {
				encoded[1], encoded[2] = encoded[2], encoded[1]
			}
			out = append(out, encoded)

			key := uint32(encoded[0])<<24 | uint32(encoded[1])<<16 | uint32(encoded[2])<<8 | uint32(encoded[3])
			if prev, ok := seen[key]; ok && prev != byte(byteVal) {
				return nil, errors.New("sudoku: decode key collision")
			}
			seen[key] = byte(byteVal)
			t.decodeInsert(key, byte(byteVal))
		}

		t.EncodeTable[byteVal] = out
	}

	// Optional: accelerate decode for ASCII-pure scenarios.
	// This uses an off-heap 16MiB lookup table indexed by 4*6-bit hint IDs.
	if t.IsASCII {
		if err := t.buildDecodeLUT24(seen); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func decodeHash32(x uint32) uint32 {
	// A small 32-bit mixer (similar spirit to murmur finalizer).
	x ^= x >> 16
	x *= 0x7feb352d
	x ^= x >> 15
	x *= 0x846ca68b
	x ^= x >> 16
	return x
}

func (t *Table) decodeInsert(key uint32, val byte) {
	if t == nil || len(t.decodeKeys) == 0 {
		return
	}
	mask := t.decodeMask
	idx := decodeHash32(key) & mask
	for {
		k := t.decodeKeys[idx]
		if k == emptyDecodeKey || k == key {
			t.decodeKeys[idx] = key
			t.decodeVals[idx] = val
			return
		}
		idx = (idx + 1) & mask
	}
}

func (t *Table) Decode(key uint32) (byte, bool) {
	if t != nil && len(t.decodeLUT24) == 1<<24 {
		b0 := byte(key >> 24)
		b1 := byte(key >> 16)
		b2 := byte(key >> 8)
		b3 := byte(key)
		i0, i1, i2, i3 := t.hintTo6[b0], t.hintTo6[b1], t.hintTo6[b2], t.hintTo6[b3]
		// In ASCII mode, keys are always hints; keep a fallback for safety.
		if t.hintTo6OK[b0] && t.hintTo6OK[b1] && t.hintTo6OK[b2] && t.hintTo6OK[b3] {
			idx := (uint32(i0) << 18) | (uint32(i1) << 12) | (uint32(i2) << 6) | uint32(i3)
			v := t.decodeLUT24[idx]
			if v != 0 {
				return byte(v - 1), true
			}
			return 0, false
		}
	}

	if t == nil || len(t.decodeKeys) == 0 {
		return 0, false
	}
	mask := t.decodeMask
	idx := decodeHash32(key) & mask
	for {
		k := t.decodeKeys[idx]
		if k == key {
			return t.decodeVals[idx], true
		}
		if k == emptyDecodeKey {
			return 0, false
		}
		idx = (idx + 1) & mask
	}
}

func (t *Table) buildHintTo6() {
	if t == nil || t.layout == nil {
		return
	}
	// Canonical 6-bit ID is (value2b<<4 | pos4b). This is stable across layouts.
	for value2b := byte(0); value2b < 4; value2b++ {
		for pos4b := byte(0); pos4b < 16; pos4b++ {
			b := t.layout.encodeHint(value2b, pos4b)
			id := (value2b << 4) | (pos4b & 0x0F)
			t.hintTo6[b] = id
			t.hintTo6OK[b] = true
		}
	}
	// In prefer_ascii mode we also accept '\n' as an on-wire alias for 0x7F.
	if t.IsASCII {
		t.hintTo6['\n'] = t.hintTo6[0x7F]
		t.hintTo6OK['\n'] = true
	}
}

func uniqueCombosByGridRef() [][]uint16 {
	uniqueCombosOnce.Do(func() {
		allGrids := allGridsRef()
		combinations := comb4Ref()
		if len(allGrids) == 0 || len(combinations) == 0 {
			uniqueCombosByGrid = nil
			return
		}

		patternCount := len(combinations) << 8 // 256 value patterns per combination.
		counts := make([]uint16, patternCount)
		firstGrid := make([]uint16, patternCount)

		for gi, g := range allGrids {
			for ci, positions := range combinations {
				id := hintPatternID(ci, positions, g)
				if counts[id] == 0 {
					firstGrid[id] = uint16(gi)
				}
				if counts[id] < ^uint16(0) {
					counts[id]++
				}
			}
		}

		uniqueCombosByGrid = make([][]uint16, len(allGrids))
		for id, c := range counts {
			if c != 1 {
				continue
			}
			gi := firstGrid[id]
			comb := uint16(id >> 8)
			uniqueCombosByGrid[gi] = append(uniqueCombosByGrid[gi], comb)
		}
	})
	return uniqueCombosByGrid
}

func hintPatternID(comboIdx int, positions [4]uint8, g Grid) int {
	p0, p1, p2, p3 := positions[0], positions[1], positions[2], positions[3]
	v0 := (g[p0] - 1) & 0x03
	v1 := (g[p1] - 1) & 0x03
	v2 := (g[p2] - 1) & 0x03
	v3 := (g[p3] - 1) & 0x03
	valCode := int(v0)<<6 | int(v1)<<4 | int(v2)<<2 | int(v3)
	return (comboIdx << 8) | valCode
}
