package sudoku

import (
	"net"
	"testing"
)

func TestPackedConn_CloseReadWrite(t *testing.T) {
	t.Parallel()

	s, c := net.Pipe()
	defer s.Close()
	defer c.Close()

	table, err := NewTable("seed-1", "prefer_entropy")
	if err != nil {
		t.Fatal(err)
	}
	pc := NewPackedConn(s, table, 0, 0)
	if err := pc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := pc.CloseRead(); err != nil {
		t.Fatal(err)
	}
	if err := pc.Flush(); err != nil {
		t.Fatal(err)
	}
}
