//go:build windows || plan9 || js || wasip1

package sudoku

func makeLUT24Buffer(size int) ([]uint16, error) {
	return make([]uint16, size), nil
}

func protectLUT24Buffer(buf []uint16) error {
	// No-op on Windows/others where Mprotect is complex or unavailable
	return nil
}
