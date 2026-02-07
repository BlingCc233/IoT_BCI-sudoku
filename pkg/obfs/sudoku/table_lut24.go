package sudoku

import (
	"fmt"
)

func (t *Table) buildDecodeLUT24(keys map[uint32]byte) error {
	if t == nil || !t.IsASCII || len(keys) == 0 {
		return nil
	}

	const lutSize = 1 << 24 // 4*6-bit index space
	u16, err := makeLUT24Buffer(lutSize)
	if err != nil {
		// Fall back to open addressing on platforms where mmap isn't available.
		return nil
	}

	for k, v := range keys {
		b0 := byte(k >> 24)
		b1 := byte(k >> 16)
		b2 := byte(k >> 8)
		b3 := byte(k)

		if !(t.hintTo6OK[b0] && t.hintTo6OK[b1] && t.hintTo6OK[b2] && t.hintTo6OK[b3]) {
			return fmt.Errorf("sudoku: lut24 build: non-hint byte in key")
		}

		i0, i1, i2, i3 := t.hintTo6[b0], t.hintTo6[b1], t.hintTo6[b2], t.hintTo6[b3]
		idx := (uint32(i0) << 18) | (uint32(i1) << 12) | (uint32(i2) << 6) | uint32(i3)
		want := uint16(v) + 1
		if prev := u16[idx]; prev != 0 && prev != want {
			return fmt.Errorf("sudoku: lut24 build: index collision")
		}
		u16[idx] = want
	}

	// Make it read-only after initialization to reduce accidental writes.
	// Make it read-only after initialization to reduce accidental writes.
	_ = protectLUT24Buffer(u16)
	t.decodeLUT24 = u16
	return nil
}
