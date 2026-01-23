package bci

import (
	"encoding/binary"
	"math"
	"math/rand"
	"time"
)

// Generator produces synthetic BCI-like sample frames for reproducible testing.
//
// Output format (binary, big-endian):
// - uint64 timestamp_unix_nano
// - uint16 channels
// - uint16 sample_rate_hz
// - uint16 samples_per_channel (per frame)
// - int16[channels*samples_per_channel] interleaved by channel-major
type Generator struct {
	Channels          int
	SampleRateHz      int
	SamplesPerChannel int
	AlphaHz           float64
	NoiseStdDev       float64
	DeterministicSeed int64

	rng *rand.Rand
	t0  time.Time
	n   int64
}

func (g *Generator) Init() {
	seed := g.DeterministicSeed
	if seed == 0 {
		seed = 1
	}
	g.rng = rand.New(rand.NewSource(seed))
	g.t0 = time.Now()
	g.n = 0
}

func (g *Generator) NextFrame() []byte {
	if g.rng == nil {
		g.Init()
	}
	ch := g.Channels
	if ch <= 0 {
		ch = 8
	}
	sr := g.SampleRateHz
	if sr <= 0 {
		sr = 256
	}
	spc := g.SamplesPerChannel
	if spc <= 0 {
		spc = 32
	}
	alpha := g.AlphaHz
	if alpha <= 0 {
		alpha = 10.0
	}
	noise := g.NoiseStdDev
	if noise <= 0 {
		noise = 0.15
	}

	// Header + samples.
	sampleCount := ch * spc
	out := make([]byte, 8+2+2+2+sampleCount*2)
	i := 0

	ts := time.Now().UnixNano()
	// Also keep deterministic progression for consistency across machines.
	if g.DeterministicSeed != 0 {
		ts = g.t0.Add(time.Duration(g.n*int64(time.Second)) / time.Duration(sr)).UnixNano()
	}
	binary.BigEndian.PutUint64(out[i:i+8], uint64(ts))
	i += 8
	binary.BigEndian.PutUint16(out[i:i+2], uint16(ch))
	i += 2
	binary.BigEndian.PutUint16(out[i:i+2], uint16(sr))
	i += 2
	binary.BigEndian.PutUint16(out[i:i+2], uint16(spc))
	i += 2

	// EEG-ish waveform: per-channel phase offset + shared alpha rhythm + noise.
	for c := 0; c < ch; c++ {
		phase := float64(c) * 0.3
		for s := 0; s < spc; s++ {
			t := float64(g.n+int64(s)) / float64(sr)
			v := 0.6*math.Sin(2*math.Pi*alpha*t+phase) + 0.2*math.Sin(2*math.Pi*2.0*t) + noise*gauss(g.rng)
			// Scale to int16.
			x := int16(clamp(v*16000.0, -32768, 32767))
			binary.BigEndian.PutUint16(out[i:i+2], uint16(x))
			i += 2
		}
	}

	g.n += int64(spc)
	return out
}

func gauss(r *rand.Rand) float64 {
	// Box-Muller.
	u1 := r.Float64()
	if u1 < 1e-12 {
		u1 = 1e-12
	}
	u2 := r.Float64()
	return math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2*math.Pi*u2)
}

func clamp(x float64, lo float64, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}
