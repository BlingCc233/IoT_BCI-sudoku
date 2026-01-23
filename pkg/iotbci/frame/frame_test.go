package frame

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	payload := []byte("bci-frame")
	if err := Write(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, MaxFrameSizeDefault)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("mismatch")
	}
}

func TestFrameErrors(t *testing.T) {
	t.Parallel()

	if err := Write(nil, []byte("x")); err == nil {
		t.Fatalf("expected error")
	}
	if _, err := Read(nil, 1); err == nil {
		t.Fatalf("expected error")
	}

	// Invalid declared length.
	var buf bytes.Buffer
	_, _ = buf.Write([]byte{0, 0, 0, 10})
	_, err := Read(&buf, 5)
	if err == nil {
		t.Fatalf("expected error")
	}
}
