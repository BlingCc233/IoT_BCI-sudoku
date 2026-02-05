package sudoku

import "testing"

func TestNewTableAndTableSet(t *testing.T) {
	t.Parallel()

	t1, err := NewTable("seed-1", "prefer_entropy")
	if err != nil {
		t.Fatal(err)
	}
	if t1.IsASCII {
		t.Fatalf("expected entropy table")
	}
	if len(t1.decodeKeys) == 0 || len(t1.EncodeTable[0]) == 0 {
		t.Fatalf("table not initialized")
	}
	enc := t1.EncodeTable[0][0]
	key := uint32(enc[0])<<24 | uint32(enc[1])<<16 | uint32(enc[2])<<8 | uint32(enc[3])
	if got, ok := t1.Decode(key); !ok || got != 0 {
		t.Fatalf("decode mismatch: got=%d ok=%v", got, ok)
	}

	t2, err := NewTable("seed-1", "prefer_ascii")
	if err != nil {
		t.Fatal(err)
	}
	if !t2.IsASCII {
		t.Fatalf("expected ascii table")
	}

	ts, err := NewTableSet("seed-2", "prefer_entropy", []string{"xppppxvv", "vppxppvx"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ts.Candidates()) != 2 {
		t.Fatalf("expected 2 candidates")
	}

	// Ensure nil receiver is safe.
	var nilTS *TableSet
	if nilTS.Candidates() != nil {
		t.Fatalf("expected nil")
	}
}

func TestResolveLayout_EntropyAndASCII(t *testing.T) {
	t.Parallel()

	ent, err := resolveLayout("prefer_entropy", "")
	if err != nil {
		t.Fatal(err)
	}
	if ent.name != "entropy" {
		t.Fatalf("expected entropy layout, got %q", ent.name)
	}
	for g := 0; g < 64; g++ {
		b := ent.encodeGroup(byte(g))
		out, ok := ent.decodeGroup(b)
		if !ok || out != byte(g) {
			t.Fatalf("group mismatch: %d -> %d (ok=%v)", g, out, ok)
		}
	}

	asc, err := resolveLayout("prefer_ascii", "xppppxvv")
	if err != nil {
		t.Fatal(err)
	}
	if asc.name != "ascii" {
		t.Fatalf("expected ascii layout, got %q", asc.name)
	}
	if !asc.isHint('\n') {
		t.Fatalf("expected newline alias to be a hint in ascii layout")
	}
}
