package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	MaxFrameSizeDefault = 1 << 20 // 1 MiB
)

func Write(w io.Writer, payload []byte) error {
	if w == nil {
		return fmt.Errorf("frame: nil writer")
	}
	if len(payload) > int(^uint32(0)) {
		return fmt.Errorf("frame: payload too large: %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func Read(r io.Reader, maxSize int) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("frame: nil reader")
	}
	if maxSize <= 0 {
		maxSize = MaxFrameSizeDefault
	}

	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(header[:]))
	if n < 0 || n > maxSize {
		return nil, fmt.Errorf("frame: invalid length %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
