package bench

import (
	"runtime"
	"sync"
	"time"
)

type MemPeak struct {
	HeapAlloc uint64
	HeapInuse uint64
	Sys       uint64
}

type MemSampler struct {
	stopCh chan struct{}
	wg     sync.WaitGroup

	mu   sync.Mutex
	peak MemPeak
}

func StartMemSampler(interval time.Duration) *MemSampler {
	if interval <= 0 {
		interval = 5 * time.Millisecond
	}
	s := &MemSampler{
		stopCh: make(chan struct{}),
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		s.mu.Lock()
		s.peak.HeapAlloc = ms.HeapAlloc
		s.peak.HeapInuse = ms.HeapInuse
		s.peak.Sys = ms.Sys
		s.mu.Unlock()

		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-t.C:
				runtime.ReadMemStats(&ms)
				s.mu.Lock()
				if ms.HeapAlloc > s.peak.HeapAlloc {
					s.peak.HeapAlloc = ms.HeapAlloc
				}
				if ms.HeapInuse > s.peak.HeapInuse {
					s.peak.HeapInuse = ms.HeapInuse
				}
				if ms.Sys > s.peak.Sys {
					s.peak.Sys = ms.Sys
				}
				s.mu.Unlock()
			}
		}
	}()
	return s
}

func (s *MemSampler) Stop() MemPeak {
	if s == nil {
		return MemPeak{}
	}
	close(s.stopCh)
	s.wg.Wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}
