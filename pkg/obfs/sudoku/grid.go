package sudoku

// Grid represents a 4x4 Sudoku grid (values 1..4).
//
// Internally we index cells as 0..15 (row-major, 4 columns).
type Grid [16]uint8

// GenerateAllGrids returns all valid 4x4 Sudoku grids.
//
// NOTE: This is deterministic and independent of the key/material used by the protocol.
func GenerateAllGrids() []Grid {
	var grids []Grid
	var g Grid

	var backtrack func(idx int)
	backtrack = func(idx int) {
		if idx == 16 {
			grids = append(grids, g)
			return
		}
		row, col := idx/4, idx%4
		boxRow, boxCol := (row/2)*2, (col/2)*2

		for num := uint8(1); num <= 4; num++ {
			valid := true
			for i := 0; i < 4; i++ {
				if g[row*4+i] == num || g[i*4+col] == num {
					valid = false
					break
				}
			}
			if valid {
				for r := 0; r < 2; r++ {
					for c := 0; c < 2; c++ {
						if g[(boxRow+r)*4+(boxCol+c)] == num {
							valid = false
							break
						}
					}
				}
			}

			if valid {
				g[idx] = num
				backtrack(idx + 1)
				g[idx] = 0
			}
		}
	}
	backtrack(0)
	return grids
}
