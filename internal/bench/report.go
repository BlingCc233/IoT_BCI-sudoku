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

	WireEntropy    float64 `json:"wire_entropy"`
	WireASCIIRatio float64 `json:"wire_ascii_ratio"`

	PeakHeapAllocBytes uint64 `json:"peak_heap_alloc_bytes"`
	PeakHeapInuseBytes uint64 `json:"peak_heap_inuse_bytes"`
	PeakSysBytes       uint64 `json:"peak_sys_bytes"`

	DurationMillis float64 `json:"duration_ms"`
}

type Report struct {
	GeneratedAt time.Time `json:"generated_at"`

	CoreSourceBytes int64 `json:"core_source_bytes"`

	Results []ProtocolResult `json:"results"`
}
