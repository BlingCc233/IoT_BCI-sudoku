package main

import (
	"context"
	"testing"
	"time"
)

func TestSignalContext_StopCancels(t *testing.T) {
	t.Parallel()

	ctx, stop := signalContext(context.Background())
	stop()

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("expected context cancellation")
	}
}
