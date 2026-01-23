package bench

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunAll_Smoke(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repoRoot, err := filepath.Abs(filepath.Join(wd, "..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	rep, err := RunAll(ctx, repoRoot, RunConfig{Messages: 10, PayloadSize: 32})
	if err != nil {
		t.Fatal(err)
	}
	if rep.CoreSourceBytes <= 0 {
		t.Fatalf("expected core source bytes > 0")
	}
	if len(rep.Results) != 6 {
		t.Fatalf("expected 6 results, got %d", len(rep.Results))
	}
}
