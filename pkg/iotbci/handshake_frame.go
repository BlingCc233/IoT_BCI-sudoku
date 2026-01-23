package iotbci

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	handshakeVersion byte = 0x01
)

const (
	hsMsgClientHello  byte = 0x01
	hsMsgServerHello  byte = 0x02
	hsMsgClientFinish byte = 0x03
)

const handshakeHeaderSize = 4 + 1 + 1 + 2

func writeHandshakeFrame(w io.Writer, msgType byte, body []byte) error {
	if w == nil {
		return fmt.Errorf("%w: nil writer", ErrProtocolViolation)
	}
	if len(body) > int(^uint16(0)) {
		return fmt.Errorf("%w: handshake body too large: %d", ErrProtocolViolation, len(body))
	}

	var header [handshakeHeaderSize]byte
	copy(header[0:4], []byte(defaultHandshakeMagic))
	header[4] = handshakeVersion
	header[5] = msgType
	binary.BigEndian.PutUint16(header[6:8], uint16(len(body)))

	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, body)
}

func readHandshakeFrame(r io.Reader, maxBody int) (byte, []byte, error) {
	if r == nil {
		return 0, nil, fmt.Errorf("%w: nil reader", ErrProtocolViolation)
	}
	if maxBody <= 0 {
		maxBody = 16 * 1024
	}

	var header [handshakeHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	if string(header[0:4]) != defaultHandshakeMagic {
		return 0, nil, fmt.Errorf("%w: bad magic", ErrProtocolViolation)
	}
	if header[4] != handshakeVersion {
		return 0, nil, fmt.Errorf("%w: unsupported version %d", ErrProtocolViolation, header[4])
	}
	msgType := header[5]
	n := int(binary.BigEndian.Uint16(header[6:8]))
	if n < 0 || n > maxBody {
		return 0, nil, fmt.Errorf("%w: invalid handshake length %d", ErrProtocolViolation, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return msgType, body, nil
}
