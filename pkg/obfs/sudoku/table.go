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
	DecodeMap   map[uint32]byte
	PaddingPool []byte
	IsASCII     bool
	layout      *byteLayout
}

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
		DecodeMap: make(map[uint32]byte, 256*64),
		IsASCII:   layout.name == "ascii",
		layout:    layout,
	}
	t.PaddingPool = append(t.PaddingPool, layout.paddingPool...)

	// Generate all grids and deterministically shuffle them with key.
	allGrids := allGridsRef()
	h := sha256.Sum256([]byte(key))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	rng := rand.New(rand.NewSource(seed))

	shuffled := make([]Grid, len(allGrids))
	copy(shuffled, allGrids)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	combinations := comb4Ref()

	// Build per-byte mapping.
	for byteVal := 0; byteVal < 256; byteVal++ {
		targetGrid := shuffled[byteVal]

		for _, positions := range combinations {
			// Extract raw (pos,val) hints.
			var rawParts [4]struct {
				pos uint8
				val uint8
			}
			for i, p := range positions {
				rawParts[i] = struct {
					pos uint8
					val uint8
				}{pos: p, val: targetGrid[p]} // val: 1..4
			}

			// Uniqueness check: the 4 hints must match exactly one grid in the full set.
			matchCount := 0
			for _, g := range allGrids {
				match := true
				for _, hp := range rawParts {
					if g[hp.pos] != hp.val {
						match = false
						break
					}
				}
				if match {
					matchCount++
					if matchCount > 1 {
						break
					}
				}
			}
			if matchCount != 1 {
				continue
			}

			var encoded [4]byte
			for i, hp := range rawParts {
				encoded[i] = t.layout.encodeHint(hp.val-1, hp.pos)
			}
			t.EncodeTable[byteVal] = append(t.EncodeTable[byteVal], encoded)

			key := packHintsToKey(encoded)
			t.DecodeMap[key] = byte(byteVal)
		}
	}
	return t, nil
}

func packHintsToKey(hints [4]byte) uint32 {
	// Sorting network for 4 elements (bubble sort unrolled).
	if hints[0] > hints[1] {
		hints[0], hints[1] = hints[1], hints[0]
	}
	if hints[2] > hints[3] {
		hints[2], hints[3] = hints[3], hints[2]
	}
	if hints[0] > hints[2] {
		hints[0], hints[2] = hints[2], hints[0]
	}
	if hints[1] > hints[3] {
		hints[1], hints[3] = hints[3], hints[1]
	}
	if hints[1] > hints[2] {
		hints[1], hints[2] = hints[2], hints[1]
	}
	return uint32(hints[0])<<24 | uint32(hints[1])<<16 | uint32(hints[2])<<8 | uint32(hints[3])
}

func packHintsToKey4(b0, b1, b2, b3 byte) uint32 {
	// Sorting network for 4 elements (bubble sort unrolled).
	if b0 > b1 {
		b0, b1 = b1, b0
	}
	if b2 > b3 {
		b2, b3 = b3, b2
	}
	if b0 > b2 {
		b0, b2 = b2, b0
	}
	if b1 > b3 {
		b1, b3 = b3, b1
	}
	if b1 > b2 {
		b1, b2 = b2, b1
	}
	return uint32(b0)<<24 | uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)
}
