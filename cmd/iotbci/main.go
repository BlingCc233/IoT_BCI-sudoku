package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/node"
)

func main() {
	var (
		cfgPath = flag.String("c", "", "config file path (json)")
		timeout = flag.Duration("timeout", 0, "optional overall timeout (0 = no)")
	)
	flag.Parse()
	if *cfgPath == "" {
		fatal(fmt.Errorf("-c is required"))
	}

	cfg, err := node.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	ctx, stop := signalContext(ctx)
	defer stop()

	switch cfg.Mode {
	case "server":
		fatal(node.Serve(ctx, cfg))
	case "client":
		fatal(node.DialAndRun(ctx, cfg))
	default:
		fatal(fmt.Errorf("invalid mode: %s", cfg.Mode))
	}
}

func signalContext(parent context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		close(ch)
		cancel()
	}
}

func fatal(err error) {
	if err == nil {
		return
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		// Normal exit conditions.
		os.Exit(0)
	}
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	time.Sleep(10 * time.Millisecond)
	os.Exit(1)
}
