package mux

import (
	"fmt"
	"io"
)

const (
	// MagicByte marks a session that carries multiple logical streams.
	MagicByte byte = 0xED
	version   byte = 0x01
)

func WritePreface(w io.Writer) error {
	if w == nil {
		return fmt.Errorf("nil writer")
	}
	_, err := w.Write([]byte{MagicByte, version})
	return err
}

func ReadPreface(r io.Reader) error {
	if r == nil {
		return fmt.Errorf("nil reader")
	}
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] != MagicByte {
		return fmt.Errorf("invalid mux magic: %d", b[0])
	}
	if b[1] != version {
		return fmt.Errorf("unsupported mux version: %d", b[1])
	}
	return nil
}
