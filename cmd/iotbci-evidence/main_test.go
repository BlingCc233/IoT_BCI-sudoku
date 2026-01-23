package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestToolName(t *testing.T) {
	t.Parallel()

	got := toolName("iotbci-report")
	if runtime.GOOS == "windows" {
		if got != "iotbci-report.exe" {
			t.Fatalf("unexpected toolName: %q", got)
		}
	} else {
		if got != "iotbci-report" {
			t.Fatalf("unexpected toolName: %q", got)
		}
	}
}

func TestJoinPorts(t *testing.T) {
	t.Parallel()

	if got := joinPorts([]uint16{80, 443}); got != "80,443" {
		t.Fatalf("unexpected joinPorts: %q", got)
	}
}

func TestBPFFilter(t *testing.T) {
	t.Parallel()

	if got := bpfFilter(nil, nil); got != "" {
		t.Fatalf("unexpected empty filter: %q", got)
	}
	if got := bpfFilter([]uint16{123}, nil); got != "tcp port 123" {
		t.Fatalf("unexpected tcp filter: %q", got)
	}
	if got := bpfFilter(nil, []uint16{53}); got != "udp port 53" {
		t.Fatalf("unexpected udp filter: %q", got)
	}
	if got := bpfFilter([]uint16{1}, []uint16{2}); got != "(tcp port 1 or udp port 2)" {
		t.Fatalf("unexpected combined filter: %q", got)
	}
}

func TestBuildTool(t *testing.T) {
	t.Parallel()

	root := findRepoRoot(t)
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, toolName("iotbci-report"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := buildTool(ctx, root, outPath, "", "./cmd/iotbci-report"); err != nil {
		t.Fatalf("buildTool: %v", err)
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected output binary: %v", err)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			t.Fatalf("go.mod not found from %s", dir)
		}
		dir = next
	}
}
