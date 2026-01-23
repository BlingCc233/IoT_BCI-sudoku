package iotbci

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/BlingCc233/IoT_BCI-sudoku/pkg/obfs/sudoku"
)

type spyReadWriter struct {
	r io.Reader
	w io.Writer

	closeReadCalled  atomic.Bool
	closeWriteCalled atomic.Bool
}

func (s *spyReadWriter) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *spyReadWriter) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *spyReadWriter) CloseRead() error {
	s.closeReadCalled.Store(true)
	return nil
}
func (s *spyReadWriter) CloseWrite() error {
	s.closeWriteCalled.Store(true)
	return nil
}

func TestDirectionalConn_CloseHooks(t *testing.T) {
	t.Parallel()

	baseA, baseB := net.Pipe()
	defer baseA.Close()
	defer baseB.Close()

	var closerCalls atomic.Int32
	closer := func() error {
		closerCalls.Add(1)
		return nil
	}

	var w bytes.Buffer
	spy := &spyReadWriter{
		r: bytes.NewReader([]byte("in")),
		w: &w,
	}
	c := newDirectionalConn(baseA, spy, spy, closer, closer).(*directionalConn)

	buf := make([]byte, 2)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "in" {
		t.Fatalf("read mismatch: %q", string(buf))
	}
	if _, err := c.Write([]byte("out")); err != nil {
		t.Fatal(err)
	}
	if w.String() != "out" {
		t.Fatalf("write mismatch: %q", w.String())
	}

	_ = c.CloseRead()
	if !spy.closeReadCalled.Load() {
		t.Fatalf("expected CloseRead on reader")
	}

	_ = c.CloseWrite()
	if !spy.closeWriteCalled.Load() {
		t.Fatalf("expected CloseWrite on writer")
	}
	if closerCalls.Load() != 2 {
		t.Fatalf("expected closers called")
	}

	_ = c.Close()
}

func TestDownlinkModeByte(t *testing.T) {
	t.Parallel()
	if downlinkModeByte(true) != DownlinkModePure {
		t.Fatalf("expected pure")
	}
	if downlinkModeByte(false) != DownlinkModePacked {
		t.Fatalf("expected packed")
	}
}

func TestBuildObfsConnTypes(t *testing.T) {
	t.Parallel()

	table, err := sudoku.NewTableWithCustom("seed", "prefer_entropy", "xppppxvv")
	if err != nil {
		t.Fatal(err)
	}
	obfs := ObfsOptions{
		ASCII:              "prefer_entropy",
		CustomTables:       []string{"xppppxvv"},
		PaddingMin:         0,
		PaddingMax:         0,
		EnablePureDownlink: false,
	}

	baseA, baseB := net.Pipe()
	defer baseA.Close()
	defer baseB.Close()

	cConn := buildObfsConnForClient(baseA, table, obfs)
	if _, ok := cConn.(*directionalConn); !ok {
		t.Fatalf("expected directionalConn for packed downlink client")
	}

	uplink, sConn := buildObfsConnForServer(baseB, table, obfs, false)
	if uplink == nil || sConn == nil {
		t.Fatalf("expected conns")
	}
	if _, ok := sConn.(*directionalConn); !ok {
		t.Fatalf("expected directionalConn for packed downlink server")
	}
}
