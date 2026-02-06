package main

import (
	"runtime"
	"sort"
	"time"

	"github.com/BlingCc233/IoT_BCI-sudoku/internal/bench"
)

func buildPayload(size int) []byte {
	if size <= 0 {
		size = 256
	}
	p := make([]byte, size)
	for i := range p {
		p[i] = byte(i)
	}
	return p
}

func readFull(r ioReader, b []byte) error {
	for off := 0; off < len(b); {
		n, err := r.Read(b[off:])
		if err != nil {
			return err
		}
		off += n
	}
	return nil
}

func writeFull(w ioWriter, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

type ioReader interface {
	Read(p []byte) (int, error)
}

type ioWriter interface {
	Write(p []byte) (int, error)
}

func warmupCount(messages int) int {
	if messages <= 0 {
		return 0
	}
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

func avgDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	var sum time.Duration
	for _, x := range d {
		sum += x
	}
	return sum / time.Duration(len(d))
}

func percentileDuration(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(d))
	copy(cp, d)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	if p <= 0 {
		return cp[0]
	}
	if p >= 1 {
		return cp[len(cp)-1]
	}
	idx := int(float64(len(cp)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

func startMemPhaseSampler(interval time.Duration) (*bench.MemSampler, bench.MemPeak) {
	if interval <= 0 {
		interval = 5 * time.Millisecond
	}
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := bench.MemPeak{
		HeapAlloc: ms.HeapAlloc,
		HeapInuse: ms.HeapInuse,
		Sys:       ms.Sys,
	}
	return bench.StartMemSampler(interval), base
}

func stopMemPhaseSampler(mem *bench.MemSampler, base bench.MemPeak) bench.MemPeak {
	_ = base
	return mem.Stop()
}

func memDeltaFromBase(peak, base bench.MemPeak) bench.MemPeak {
	d := peak
	if d.HeapAlloc > base.HeapAlloc {
		d.HeapAlloc -= base.HeapAlloc
	} else {
		d.HeapAlloc = 0
	}
	if d.HeapInuse > base.HeapInuse {
		d.HeapInuse -= base.HeapInuse
	} else {
		d.HeapInuse = 0
	}
	if d.Sys > base.Sys {
		d.Sys -= base.Sys
	} else {
		d.Sys = 0
	}
	return d
}

func resultFromStats(name string, cfg bench.RunConfig, dur time.Duration, peak bench.MemPeak, peakDelta bench.MemPeak, stats *bench.WireStats, rtts []time.Duration) bench.ProtocolResult {
	if cfg.Messages <= 0 {
		cfg.Messages = 1
	}
	if cfg.PayloadSize <= 0 {
		cfg.PayloadSize = 1
	}
	if stats == nil {
		stats = &bench.WireStats{}
	}

	payloadBytes := int64(cfg.Messages * cfg.PayloadSize * 2)
	wireBytes := stats.BytesWritten.Load() + stats.BytesRead.Load()

	writtenFreq := stats.SnapshotWrittenFreq()
	byteStats := bench.ComputeByteStats(writtenFreq)

	first := stats.FirstWriteUnixNano.Load()
	last := stats.LastWriteUnixNano.Load()
	activeMillis := 0.0
	if first > 0 && last >= first {
		activeMillis = float64(time.Duration(last-first)) / float64(time.Millisecond)
	}

	avg := avgDuration(rtts)
	p95 := percentileDuration(rtts, 0.95)

	durSec := dur.Seconds()
	payloadBps := 0.0
	wireBps := 0.0
	if durSec > 0 {
		payloadBps = float64(payloadBytes) / durSec
		wireBps = float64(wireBytes) / durSec
	}
	overhead := 0.0
	if payloadBytes > 0 {
		overhead = float64(wireBytes) / float64(payloadBytes)
	}

	return bench.ProtocolResult{
		Name:                          name,
		Messages:                      cfg.Messages,
		PayloadSize:                   cfg.PayloadSize,
		PayloadBytesTotal:             payloadBytes,
		WireBytesTotal:                wireBytes,
		OverheadRatio:                 overhead,
		AvgRTTMillis:                  float64(avg) / float64(time.Millisecond),
		P95RTTMillis:                  float64(p95) / float64(time.Millisecond),
		WireWriteCalls:                stats.WriteCalls.Load(),
		WireReadCalls:                 stats.ReadCalls.Load(),
		WireWriteSizeBinsLog2:         stats.SnapshotWriteSizeBins(),
		WireWriteInterArrivalMsBinsL2: stats.SnapshotWriteInterArrivalMsBins(),
		WireWriteSizeSeqSample:        stats.SnapshotWriteSizeSeq(),
		WireWriteIATMsSeqSample:       stats.SnapshotWriteIATMsSeq(),
		WireActiveDurationMillis:      activeMillis,
		WireEntropy:                   byteStats.Entropy,
		WireASCIIRatio:                byteStats.ASCIIRatio,
		PeakHeapAllocBytes:            peak.HeapAlloc,
		PeakHeapInuseBytes:            peak.HeapInuse,
		PeakSysBytes:                  peak.Sys,
		PhaseDeltaHeapAllocBytes:      peakDelta.HeapAlloc,
		PhaseDeltaHeapInuseBytes:      peakDelta.HeapInuse,
		PhaseDeltaSysBytes:            peakDelta.Sys,
		PayloadThroughputBps:          payloadBps,
		WireThroughputBps:             wireBps,
		DurationMillis:                float64(dur) / float64(time.Millisecond),
	}
}
