package bci

import (
	"encoding/binary"
	"testing"
)

func TestGeneratorDeterministic(t *testing.T) {
	t.Parallel()

	g := &Generator{
		Channels:          4,
		SampleRateHz:      100,
		SamplesPerChannel: 10,
		DeterministicSeed: 123,
	}
	g.Init()

	f1 := g.NextFrame()
	f2 := g.NextFrame()
	if len(f1) != len(f2) {
		t.Fatalf("frame length mismatch")
	}
	if string(f1) == string(f2) {
		t.Fatalf("expected different frames across time")
	}

	// Header sanity.
	if len(f1) < 8+2+2+2 {
		t.Fatalf("frame too short")
	}
	ch := binary.BigEndian.Uint16(f1[8:10])
	sr := binary.BigEndian.Uint16(f1[10:12])
	spc := binary.BigEndian.Uint16(f1[12:14])
	if ch != 4 || sr != 100 || spc != 10 {
		t.Fatalf("unexpected header: ch=%d sr=%d spc=%d", ch, sr, spc)
	}
}
