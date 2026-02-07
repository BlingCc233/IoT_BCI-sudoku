//go:build !windows && !plan9 && !js && !wasip1

package sudoku

import (
	"syscall"
	"unsafe"
)

func makeLUT24Buffer(size int) ([]uint16, error) {
	raw, err := syscall.Mmap(
		-1,
		0,
		size*2, // 2 bytes per uint16
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_ANON|syscall.MAP_PRIVATE,
	)
	if err != nil {
		return nil, err
	}
	return unsafe.Slice((*uint16)(unsafe.Pointer(&raw[0])), size), nil
}

func protectLUT24Buffer(buf []uint16) error {
	if len(buf) == 0 {
		return nil
	}
	// Calculate total bytes
	sizeBytes := len(buf) * 2
	// Get pointer to start
	ptr := unsafe.Pointer(&buf[0])
	// Convert back to []byte for Mprotect
	raw := unsafe.Slice((*byte)(ptr), sizeBytes)
	return syscall.Mprotect(raw, syscall.PROT_READ)
}
