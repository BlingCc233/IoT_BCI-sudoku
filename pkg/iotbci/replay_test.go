package iotbci

import (
	"testing"
	"time"
)

func TestReplayCache_SeenOrAdd(t *testing.T) {
	t.Parallel()

	c := NewReplayCache(2, 50*time.Millisecond)
	now := time.Now()

	token1 := []byte("t1")
	token2 := []byte("t2")
	token3 := []byte("t3")

	if got := c.SeenOrAdd(token1, now); got {
		t.Fatalf("expected first insert to be unseen")
	}
	if got := c.SeenOrAdd(token1, now.Add(10*time.Millisecond)); !got {
		t.Fatalf("expected replay within window")
	}
	if got := c.SeenOrAdd(token1, now.Add(60*time.Millisecond)); got {
		t.Fatalf("expected expired token to be accepted")
	}

	// Fill and evict by insertion order (ring).
	_ = c.SeenOrAdd(token1, now)
	_ = c.SeenOrAdd(token2, now)
	_ = c.SeenOrAdd(token3, now)

	// token1 should have been evicted.
	if got := c.SeenOrAdd(token1, now.Add(1*time.Millisecond)); got {
		t.Fatalf("expected token1 to be evicted")
	}
}
