package bench

import "time"

type RunConfig struct {
	Messages    int
	PayloadSize int
}

type ProtocolResult struct {
	Name string `json:"name"`

	Messages    int `json:"messages"`
	PayloadSize int `json:"payload_size"`

	PayloadBytesTotal int64   `json:"payload_bytes_total"`
	WireBytesTotal    int64   `json:"wire_bytes_total"`
	OverheadRatio     float64 `json:"overhead_ratio"`

	AvgRTTMillis float64 `json:"avg_rtt_ms"`
	P95RTTMillis float64 `json:"p95_rtt_ms"`

	WireWriteCalls int64 `json:"wire_write_calls"`
	WireReadCalls  int64 `json:"wire_read_calls"`

	WireWriteSizeBinsLog2         [32]uint64 `json:"wire_write_size_bins_log2"`
	WireWriteInterArrivalMsBinsL2 [32]uint64 `json:"wire_write_interarrival_ms_bins_log2"`
	WireActiveDurationMillis      float64    `json:"wire_active_duration_ms"`

	WireEntropy    float64 `json:"wire_entropy"`
	WireASCIIRatio float64 `json:"wire_ascii_ratio"`

	PeakHeapAllocBytes uint64 `json:"peak_heap_alloc_bytes"`
	PeakHeapInuseBytes uint64 `json:"peak_heap_inuse_bytes"`
	PeakSysBytes       uint64 `json:"peak_sys_bytes"`

	PayloadThroughputBps float64 `json:"payload_throughput_bps"`
	WireThroughputBps    float64 `json:"wire_throughput_bps"`

	DurationMillis float64 `json:"duration_ms"`
}

type Report struct {
	GeneratedAt time.Time `json:"generated_at"`

	CoreSourceBytes int64 `json:"core_source_bytes"`

	Results []ProtocolResult `json:"results"`
}
