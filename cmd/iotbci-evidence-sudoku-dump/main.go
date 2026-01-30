package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/obfs/sudoku"
)

type dump struct {
	Key         string             `json:"key"`
	Mode        string             `json:"mode"`
	Pattern     string             `json:"pattern"`
	GridCount   int                `json:"grid_count"`
	ByteToGrid  [256]sudoku.Grid   `json:"byte_to_grid"`
	EncodeTable [256][][4]byte     `json:"encode_table"`
	PaddingPool []int              `json:"padding_pool"`
	Stats       map[string]float64 `json:"stats"`
}

func main() {
	var (
		key     = flag.String("key", "seed-custom", "table key (sha256->seed)")
		mode    = flag.String("mode", "prefer_entropy", "mode: prefer_entropy | prefer_ascii")
		pattern = flag.String("pattern", "xppppxvv", "custom x/v/p pattern (ignored in prefer_ascii)")
		out     = flag.String("out", "", "output json file (default: stdout)")
	)
	flag.Parse()

	table, err := sudoku.NewTableWithCustom(*key, *mode, *pattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build table: %v\n", err)
		os.Exit(1)
	}

	all := sudoku.GenerateAllGrids()
	shuffled := make([]sudoku.Grid, len(all))
	copy(shuffled, all)

	h := sha256.Sum256([]byte(*key))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	var byteToGrid [256]sudoku.Grid
	for i := 0; i < 256; i++ {
		byteToGrid[i] = shuffled[i]
	}

	padding := make([]int, 0, len(table.PaddingPool))
	for _, b := range table.PaddingPool {
		padding = append(padding, int(b))
	}

	totalPuzzles := 0
	minPuzzles := int(^uint(0) >> 1)
	maxPuzzles := 0
	for i := 0; i < 256; i++ {
		n := len(table.EncodeTable[i])
		totalPuzzles += n
		if n < minPuzzles {
			minPuzzles = n
		}
		if n > maxPuzzles {
			maxPuzzles = n
		}
	}

	outObj := dump{
		Key:         *key,
		Mode:        *mode,
		Pattern:     *pattern,
		GridCount:   len(all),
		ByteToGrid:  byteToGrid,
		EncodeTable: table.EncodeTable,
		PaddingPool: padding,
		Stats: map[string]float64{
			"puzzles_total": float64(totalPuzzles),
			"puzzles_min":   float64(minPuzzles),
			"puzzles_max":   float64(maxPuzzles),
			"puzzles_avg":   float64(totalPuzzles) / 256.0,
		},
	}

	blob, err := json.MarshalIndent(outObj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal json: %v\n", err)
		os.Exit(1)
	}
	blob = append(blob, '\n')

	if *out == "" {
		_, _ = os.Stdout.Write(blob)
		return
	}

	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write out: %v\n", err)
		os.Exit(1)
	}
}
