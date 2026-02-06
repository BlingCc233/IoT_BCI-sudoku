package bench

import "time"

type wireSummary struct {
	writeCalls int64
	readCalls  int64

	writeSizeBins [32]uint64
	writeIATBins  [32]uint64
	writeSizeSeq  []uint32
	writeIATMsSeq []uint32

	activeDurationMillis float64
}

func summarizeWire(a, b *WireStats) wireSummary {
	return summarizeWireMany(a, b)
}

func summarizeWireMany(stats ...*WireStats) wireSummary {
	var out wireSummary
	if len(stats) == 0 {
		return out
	}

	const maxSeq = 2048

	first := int64(0)
	last := int64(0)

	for _, s := range stats {
		if s == nil {
			continue
		}
		out.writeCalls += s.WriteCalls.Load()
		out.readCalls += s.ReadCalls.Load()

		w := s.SnapshotWriteSizeBins()
		iat := s.SnapshotWriteInterArrivalMsBins()
		for i := 0; i < 32; i++ {
			out.writeSizeBins[i] += w[i]
			out.writeIATBins[i] += iat[i]
		}
		if len(out.writeSizeSeq) < maxSeq {
			seq := s.SnapshotWriteSizeSeq()
			remain := maxSeq - len(out.writeSizeSeq)
			if len(seq) > remain {
				seq = seq[:remain]
			}
			out.writeSizeSeq = append(out.writeSizeSeq, seq...)
		}
		if len(out.writeIATMsSeq) < maxSeq {
			seq := s.SnapshotWriteIATMsSeq()
			remain := maxSeq - len(out.writeIATMsSeq)
			if len(seq) > remain {
				seq = seq[:remain]
			}
			out.writeIATMsSeq = append(out.writeIATMsSeq, seq...)
		}

		f := s.FirstWriteUnixNano.Load()
		l := s.LastWriteUnixNano.Load()
		if f != 0 && (first == 0 || f < first) {
			first = f
		}
		if l > last {
			last = l
		}
	}

	if first != 0 && last != 0 && last >= first {
		out.activeDurationMillis = float64(time.Duration(last-first)) / float64(time.Millisecond)
	}
	return out
}
