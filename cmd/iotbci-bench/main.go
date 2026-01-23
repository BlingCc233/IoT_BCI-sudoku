package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
)

func main() {
	var (
		outPath  = flag.String("out", "", "output JSON path (default: stdout)")
		msgs     = flag.Int("messages", 1000, "messages (round trips)")
		size     = flag.Int("size", 256, "payload size (bytes)")
		timeout  = flag.Duration("timeout", 30*time.Second, "overall timeout")
		repoRoot = flag.String("repo_root", "", "repo root (default: current dir)")
	)
	flag.Parse()

	root := *repoRoot
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			fatal(err)
		}
		root = wd
	}
	root, _ = filepath.Abs(root)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report, err := bench.RunAll(ctx, root, bench.RunConfig{Messages: *msgs, PayloadSize: *size})
	if err != nil {
		fatal(err)
	}

	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fatal(err)
	}

	if *outPath == "" {
		_, _ = os.Stdout.Write(append(b, '\n'))
		return
	}
	if err := os.WriteFile(*outPath, append(b, '\n'), 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
