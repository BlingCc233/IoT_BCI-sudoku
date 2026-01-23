package iotbci

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/obfs/sudoku"
)

func probeClientHelloBytes(probe []byte, obfs ObfsOptions, hsMethod AEADMethod, psk string, table *sudoku.Table, maxBody int) error {
	rc := &readOnlyConn{Reader: bytes.NewReader(probe)}
	_, obfsConn := buildObfsConnForServer(rc, table, obfs, false)

	r := obfsConn
	if hsMethod != AEADNone {
		c2sKey, s2cKey, c2sSalt, s2cSalt := DerivePSKHandshakeKeys(psk)
		hsConn, err := NewRecordConn(obfsConn, hsMethod, s2cKey[:], c2sKey[:], s2cSalt, c2sSalt)
		if err != nil {
			return err
		}
		r = hsConn
	}

	msgType, _, err := readHandshakeFrame(r, maxBody)
	if err != nil {
		return err
	}
	if msgType != hsMsgClientHello {
		return fmt.Errorf("%w: unexpected msg type %d", ErrProtocolViolation, msgType)
	}
	return nil
}

func drainBuffered(r *bufio.Reader) ([]byte, error) {
	n := r.Buffered()
	if n <= 0 {
		return nil, nil
	}
	out := make([]byte, n)
	_, err := io.ReadFull(r, out)
	return out, err
}

func selectTableByProbe(r *bufio.Reader, obfs ObfsOptions, hsMethod AEADMethod, psk string, tables []*sudoku.Table, maxBody int) (*sudoku.Table, []byte, error) {
	const (
		maxProbeBytes = 64 * 1024
		readChunk     = 4 * 1024
	)
	if len(tables) == 0 {
		return nil, nil, fmt.Errorf("no table candidates")
	}
	if len(tables) > 255 {
		return nil, nil, fmt.Errorf("too many table candidates: %d", len(tables))
	}

	probe, err := drainBuffered(r)
	if err != nil {
		return nil, nil, fmt.Errorf("drain buffered bytes failed: %w", err)
	}
	tmp := make([]byte, readChunk)

	for {
		if len(tables) == 1 {
			tail, err := drainBuffered(r)
			if err != nil {
				return nil, nil, fmt.Errorf("drain buffered bytes failed: %w", err)
			}
			probe = append(probe, tail...)
			return tables[0], probe, nil
		}

		needMore := false
		for _, table := range tables {
			err := probeClientHelloBytes(probe, obfs, hsMethod, psk, table, maxBody)
			if err == nil {
				tail, err := drainBuffered(r)
				if err != nil {
					return nil, nil, fmt.Errorf("drain buffered bytes failed: %w", err)
				}
				probe = append(probe, tail...)
				return table, probe, nil
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				needMore = true
			}
		}

		if !needMore {
			return nil, probe, fmt.Errorf("table selection failed")
		}
		if len(probe) >= maxProbeBytes {
			return nil, probe, fmt.Errorf("handshake probe exceeded %d bytes", maxProbeBytes)
		}
		n, err := r.Read(tmp)
		if n > 0 {
			probe = append(probe, tmp[:n]...)
		}
		if err != nil {
			return nil, probe, fmt.Errorf("handshake probe read failed: %w", err)
		}
	}
}
