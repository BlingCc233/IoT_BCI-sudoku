package bench

func rttWarmupCount(messages int) int {
	if messages <= 0 {
		return 0
	}
	// Skip early iterations to avoid one-time effects (allocations, cache warmup, scheduler).
	// Keep this small so we still measure steady-state, not a cherry-picked tail.
	w := messages / 10
	if w < 5 {
		w = 5
	}
	if w > 50 {
		w = 50
	}
	if w >= messages {
		w = messages / 2
	}
	if w < 0 {
		return 0
	}
	return w
}

