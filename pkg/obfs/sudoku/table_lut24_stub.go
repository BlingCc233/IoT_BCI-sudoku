//go:build !unix

package sudoku

// Non-unix platforms use the open-addressing decode table only.
// This keeps behavior correct while skipping unix mmap-specific acceleration.
func (t *Table) buildDecodeLUT24(keys map[uint32]byte) error {
	_ = t
	_ = keys
	return nil
}
