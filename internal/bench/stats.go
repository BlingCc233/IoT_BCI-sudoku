package bench

import "math"

type ByteStats struct {
	TotalBytes uint64
	Entropy    float64
	ASCIIRatio float64
}

func ComputeByteStats(freq [256]uint64) ByteStats {
	var total uint64
	for _, c := range freq {
		total += c
	}
	if total == 0 {
		return ByteStats{}
	}

	var entropy float64
	var ascii uint64
	for i, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
		if i >= 0x20 && i <= 0x7E {
			ascii += c
		}
	}
	return ByteStats{
		TotalBytes: total,
		Entropy:    entropy,
		ASCIIRatio: float64(ascii) / float64(total),
	}
}
