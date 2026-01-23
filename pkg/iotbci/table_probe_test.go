package iotbci

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/obfs/sudoku"
)

type bufferConn struct {
	bytes.Buffer
}

func (c *bufferConn) Read([]byte) (int, error)           { return 0, errors.New("read not supported") }
func (c *bufferConn) Close() error                       { return nil }
func (c *bufferConn) LocalAddr() net.Addr                { return nil }
func (c *bufferConn) RemoteAddr() net.Addr               { return nil }
func (c *bufferConn) SetDeadline(_ time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestSelectTableByProbe(t *testing.T) {
	t.Parallel()

	obfs := ObfsOptions{
		ASCII:              "prefer_entropy",
		CustomTables:       []string{"xppppxvv", "vppxppvx"},
		PaddingMin:         0,
		PaddingMax:         0,
		EnablePureDownlink: true,
	}
	psk := "test-psk-probe"
	key := "table-seed"

	ts, err := sudoku.NewTableSet(key, obfs.ASCII, obfs.CustomTables)
	if err != nil {
		t.Fatal(err)
	}
	tables := ts.Candidates()
	if len(tables) != 2 {
		t.Fatalf("expected 2 tables")
	}
	chosen := tables[1]

	// Generate a wire-level ClientHello frame using the chosen table.
	raw := &bufferConn{}
	obfsConn := buildObfsConnForClient(raw, chosen, obfs)
	c2sKey, s2cKey, c2sSalt, s2cSalt := DerivePSKHandshakeKeys(psk)
	hsConn, err := NewRecordConn(obfsConn, AEADChaCha20Poly1305, c2sKey[:], s2cKey[:], c2sSalt, s2cSalt)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeHandshakeFrame(hsConn, hsMsgClientHello, []byte("hi")); err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(bytes.NewReader(raw.Bytes()))
	gotTable, probe, err := selectTableByProbe(r, obfs, AEADChaCha20Poly1305, psk, tables, 8*1024)
	if err != nil {
		t.Fatal(err)
	}
	if gotTable != chosen {
		t.Fatalf("selected wrong table")
	}
	if !bytes.Equal(probe, raw.Bytes()) {
		t.Fatalf("probe mismatch")
	}

	// Wrong PSK should prevent decryption, thus no table should match.
	r2 := bufio.NewReader(bytes.NewReader(raw.Bytes()))
	if _, _, err := selectTableByProbe(r2, obfs, AEADChaCha20Poly1305, "wrong", tables, 8*1024); err == nil {
		t.Fatalf("expected failure")
	}
}
