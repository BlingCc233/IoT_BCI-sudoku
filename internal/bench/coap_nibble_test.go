package bench

import "testing"

func TestCoAPNibble_EncodeDecode(t *testing.T) {
	t.Parallel()

	cases := []uint16{0, 12, 13, 268, 269, 270, 1000}
	for _, n := range cases {
		nib, ext := encodeCoAPNibble(n)
		got, _, err := decodeCoAPNibble(uint16(nib), ext, 0)
		if err != nil {
			t.Fatalf("decodeCoAPNibble(%d): %v", n, err)
		}
		if got != n {
			t.Fatalf("round trip mismatch: n=%d got=%d", n, got)
		}
	}
}

func TestCoAPNibble_DecodeErrors(t *testing.T) {
	t.Parallel()

	if _, _, err := decodeCoAPNibble(13, nil, 0); err == nil {
		t.Fatalf("expected ext13 short error")
	}
	if _, _, err := decodeCoAPNibble(14, []byte{0x00}, 0); err == nil {
		t.Fatalf("expected ext14 short error")
	}
	if _, _, err := decodeCoAPNibble(15, []byte{0x00}, 0); err == nil {
		t.Fatalf("expected invalid nibble error")
	}
}
