package sudoku

import (
	"io"
	"net"
	"testing"
)

func TestConn_RecordingAndBufferedBytes(t *testing.T) {
	t.Parallel()

	sRaw, cRaw := net.Pipe()
	defer sRaw.Close()
	defer cRaw.Close()

	table, err := NewTable("seed-1", "prefer_entropy")
	if err != nil {
		t.Fatal(err)
	}

	// Server records raw on-wire bytes.
	server := NewConn(sRaw, table, 0, 0, true)
	client := NewConn(cRaw, table, 0, 0, false)

	go func() {
		_, _ = client.Write([]byte("hi"))
	}()

	buf := make([]byte, 2)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hi" {
		t.Fatalf("unexpected plaintext: %q", string(buf))
	}

	rec := server.GetBufferedAndRecorded()
	if len(rec) == 0 {
		t.Fatalf("expected recorded bytes")
	}

	server.StopRecording()
	if got := server.GetBufferedAndRecorded(); len(got) != 0 {
		t.Fatalf("expected no recorded bytes after StopRecording")
	}

	if err := server.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := server.CloseRead(); err != nil {
		t.Fatal(err)
	}
}
