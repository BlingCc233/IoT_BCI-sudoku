package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type OutputReport struct {
	Result struct {
		Name           string  `json:"name"`
		AvgRTT         float64 `json:"avg_rtt_ms"`
		PeakHeap       uint64  `json:"peak_heap_inuse_bytes"`
		DeltaHeap      uint64  `json:"phase_delta_heap_inuse_bytes"`
		Overhead       float64 `json:"overhead_ratio"`
		WireThroughput float64 `json:"wire_throughput_bps"`
	} `json:"result"`
	Proto string `json:"proto"`
	Error string `json:"error"`
}

func main() {
	files := []string{
		"sudoku_pure.json",
		"sudoku_packed.json",
		"pure_aead.json",
		"mqtt.json",
		"dtls.json",
		"coap.json",
	}

	fmt.Printf("| Protocol | RTT (ms) | Peak Heap (KB) | Delta Heap (B) | Overhead |\n")
	fmt.Printf("|---|---|---|---|---|\n")

	for _, f := range files {
		b, err := os.ReadFile("cross_region_results/" + f)
		if err != nil {
			fmt.Printf("| %s | FILE NOT FOUND | - | - | - |\n", f)
			continue
		}
		var r OutputReport
		if err := json.Unmarshal(b, &r); err != nil {
			fmt.Printf("| %s | JSON ERROR | - | - | - |\n", f)
			continue
		}

		if r.Error != "" {
			fmt.Printf("| %s | ERROR: %s | - | - | - |\n", f, r.Error)
			continue
		}

		name := r.Result.Name
		if name == "" {
			name = r.Proto
		}

		fmt.Printf("| %s | %.3f | %.1f | %d | %.2f |\n",
			name,
			r.Result.AvgRTT,
			float64(r.Result.PeakHeap)/1024.0,
			r.Result.DeltaHeap,
			r.Result.Overhead,
		)
	}
}
