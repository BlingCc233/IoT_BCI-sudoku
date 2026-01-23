package iotbci

import (
	"crypto/sha256"
	"sync"
	"time"
)

// ReplayCache is a bounded, time-windowed cache for replay detection.
//
// Memory is bounded by maxEntries; when full, it evicts in insertion order (ring).
// This is intentionally simple to keep small-memory devices predictable.
type ReplayCache struct {
	mu         sync.Mutex
	window     time.Duration
	maxEntries int

	ring []replayEntry
	next int

	seen map[[32]byte]int64 // token -> expiresAt (unix nano)
}

type replayEntry struct {
	token     [32]byte
	expiresAt int64
}

func NewReplayCache(maxEntries int, window time.Duration) *ReplayCache {
	if maxEntries <= 0 {
		maxEntries = 1024
	}
	if window <= 0 {
		window = 2 * time.Minute
	}
	return &ReplayCache{
		window:     window,
		maxEntries: maxEntries,
		ring:       make([]replayEntry, maxEntries),
		seen:       make(map[[32]byte]int64, maxEntries),
	}
}

// SeenOrAdd returns true if token has been seen within the replay window.
// Otherwise it records the token and returns false.
func (c *ReplayCache) SeenOrAdd(token []byte, now time.Time) bool {
	if c == nil {
		return false
	}
	sum := sha256.Sum256(token)
	nowN := now.UnixNano()
	exp := now.Add(c.window).UnixNano()

	c.mu.Lock()
	defer c.mu.Unlock()

	if expiresAt, ok := c.seen[sum]; ok && expiresAt > nowN {
		return true
	}

	// Evict current ring entry if occupied.
	ev := c.ring[c.next]
	if ev.expiresAt != 0 {
		if curExp, ok := c.seen[ev.token]; ok && curExp == ev.expiresAt {
			delete(c.seen, ev.token)
		}
	}

	c.ring[c.next] = replayEntry{token: sum, expiresAt: exp}
	c.next++
	if c.next >= len(c.ring) {
		c.next = 0
	}
	c.seen[sum] = exp

	return false
}
