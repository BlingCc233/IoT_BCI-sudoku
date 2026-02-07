package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Evidence struct {
	Scenarios []struct {
		Name    string `json:"name"`
		Metrics struct {
			PeakHeap  uint64 `json:"peak_heap_inuse_bytes"`
			DeltaHeap uint64 `json:"phase_delta_heap_inuse_bytes"`
		} `json:"metrics"`
	} `json:"scenarios"`
}

func main() {
	b, err := os.ReadFile("remote_evidence/evidence.json")
	if err != nil {
		panic(err)
	}
	var e Evidence
	if err := json.Unmarshal(b, &e); err != nil {
		panic(err)
	}

	fmt.Printf("| Protocol | Peak Heap (B) | Delta Heap (B) |\n")
	fmt.Printf("|---|---|---|\n")

	for _, s := range e.Scenarios {
		fmt.Printf("| %s | %d | %d |\n",
			s.Name,
			s.Metrics.PeakHeap,
			s.Metrics.DeltaHeap,
		)
	}
}
