package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Input       string    `json:"input"`

	TCPPorts []uint16 `json:"tcp_ports"`
	UDPPorts []uint16 `json:"udp_ports"`

	Packets int   `json:"packets"`
	Bytes   int64 `json:"bytes"`

	Entropy    float64 `json:"entropy"`
	ASCIIRatio float64 `json:"ascii_ratio"`

	SizeBinsLog2       map[int]int `json:"size_bins_log2"`
	InterArrivalMsBins map[int]int `json:"interarrival_ms_bins_log2"`

	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func main() {
	var (
		inPath   = flag.String("in", "", "pcap/pcapng input file")
		outDir   = flag.String("out_dir", "report_out", "output directory")
		tcpPorts = flag.String("tcp_ports", "", "comma-separated TCP ports to include")
		udpPorts = flag.String("udp_ports", "", "comma-separated UDP ports to include")
	)
	flag.Parse()
	if *inPath == "" {
		fatal(fmt.Errorf("-in is required"))
	}

	tcpList, err := parsePorts(*tcpPorts)
	if err != nil {
		fatal(err)
	}
	udpList, err := parsePorts(*udpPorts)
	if err != nil {
		fatal(err)
	}
	if len(tcpList) == 0 && len(udpList) == 0 {
		fatal(fmt.Errorf("at least one of -tcp_ports or -udp_ports is required"))
	}

	rep, err := analyze(*inPath, tcpList, udpList)
	if err != nil {
		fatal(err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}

	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "report.json"), append(b, '\n'), 0o644); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "report.md"), []byte(renderMarkdown(rep)), 0o644); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "report.html"), []byte(renderHTML(rep)), 0o644); err != nil {
		fatal(err)
	}
}

func analyze(path string, tcpPorts, udpPorts []uint16) (*report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var (
		linkType layers.LinkType
		readData func() (data []byte, ci gopacket.CaptureInfo, err error)
	)

	// Try pcapng first, then pcap.
	if ng, err := pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions); err == nil {
		linkType = ng.LinkType()
		readData = ng.ReadPacketData
	} else {
		if _, err := f.Seek(0, 0); err != nil {
			return nil, err
		}
		r, err := pcapgo.NewReader(f)
		if err != nil {
			return nil, err
		}
		linkType = r.LinkType()
		readData = r.ReadPacketData
	}

	tcpSet := make(map[uint16]struct{}, len(tcpPorts))
	for _, p := range tcpPorts {
		tcpSet[p] = struct{}{}
	}
	udpSet := make(map[uint16]struct{}, len(udpPorts))
	for _, p := range udpPorts {
		udpSet[p] = struct{}{}
	}

	var (
		rep = &report{
			GeneratedAt:        time.Now(),
			Input:              path,
			TCPPorts:           tcpPorts,
			UDPPorts:           udpPorts,
			SizeBinsLog2:       map[int]int{},
			InterArrivalMsBins: map[int]int{},
		}
		freq    [256]uint64
		lastTS  time.Time
		hasLast bool
	)

	for {
		data, ci, err := readData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		pkt := gopacket.NewPacket(data, linkType, gopacket.NoCopy)

		var payload []byte
		switch {
		case pkt.Layer(layers.LayerTypeTCP) != nil:
			tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			sp := uint16(tcp.SrcPort)
			dp := uint16(tcp.DstPort)
			if _, ok := tcpSet[sp]; !ok {
				if _, ok := tcpSet[dp]; !ok {
					continue
				}
			}
			payload = tcp.Payload
		case pkt.Layer(layers.LayerTypeUDP) != nil:
			udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			sp := uint16(udp.SrcPort)
			dp := uint16(udp.DstPort)
			if _, ok := udpSet[sp]; !ok {
				if _, ok := udpSet[dp]; !ok {
					continue
				}
			}
			payload = udp.Payload
		default:
			continue
		}

		if rep.Packets == 0 {
			rep.Start = ci.Timestamp
		}
		rep.End = ci.Timestamp
		rep.Packets++

		if len(payload) > 0 {
			rep.Bytes += int64(len(payload))
			bin := log2Bin(len(payload))
			rep.SizeBinsLog2[bin]++
			for _, b := range payload {
				freq[b]++
			}
		}

		if hasLast {
			delta := ci.Timestamp.Sub(lastTS)
			if delta < 0 {
				delta = -delta
			}
			ms := float64(delta) / float64(time.Millisecond)
			bin := int(math.Log2(ms + 1))
			if bin < 0 {
				bin = 0
			}
			if bin > 31 {
				bin = 31
			}
			rep.InterArrivalMsBins[bin]++
		}
		lastTS = ci.Timestamp
		hasLast = true
	}

	bs := computeByteStats(freq)
	rep.Entropy = bs.entropy
	rep.ASCIIRatio = bs.asciiRatio
	return rep, nil
}

type byteStats struct {
	entropy    float64
	asciiRatio float64
}

func computeByteStats(freq [256]uint64) byteStats {
	var total uint64
	for _, c := range freq {
		total += c
	}
	if total == 0 {
		return byteStats{}
	}
	var ent float64
	var ascii uint64
	for i, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		ent -= p * math.Log2(p)
		if i >= 0x20 && i <= 0x7E {
			ascii += c
		}
	}
	return byteStats{
		entropy:    ent,
		asciiRatio: float64(ascii) / float64(total),
	}
}

func log2Bin(n int) int {
	if n <= 0 {
		return 0
	}
	b := int(math.Log2(float64(n)))
	if b < 0 {
		return 0
	}
	if b >= 31 {
		return 31
	}
	return b
}

func parsePorts(s string) ([]uint16, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]uint16, 0, len(parts))
	seen := make(map[uint16]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.Atoi(p)
		if err != nil || v < 1 || v > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		u := uint16(v)
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func renderMarkdown(r *report) string {
	return fmt.Sprintf(`# Capture Report

- Generated: %s
- Input: %s
- TCP ports: %v
- UDP ports: %v

## Summary

- Packets: %d
- Payload bytes: %d
- Entropy (payload bytes): %.4f bits/byte
- ASCII ratio (payload bytes): %.4f
- Start: %s
- End: %s

## Histograms (log2 bins)

### Payload size
%s

### Inter-arrival (ms)
%s
`,
		r.GeneratedAt.Format(time.RFC3339),
		r.Input,
		r.TCPPorts,
		r.UDPPorts,
		r.Packets,
		r.Bytes,
		r.Entropy,
		r.ASCIIRatio,
		r.Start.Format(time.RFC3339Nano),
		r.End.Format(time.RFC3339Nano),
		renderHist(r.SizeBinsLog2),
		renderHist(r.InterArrivalMsBins),
	)
}

func renderHTML(r *report) string {
	return fmt.Sprintf(`<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IoT BCI Capture Report</title>
  <style>
    body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; margin:24px; color:#111}
    code,pre{background:#f6f8fa; padding:2px 6px; border-radius:6px}
    pre{padding:12px; overflow:auto}
    h1,h2{margin:0.6em 0}
    .grid{display:grid; grid-template-columns:1fr 1fr; gap:16px}
    .card{border:1px solid #ddd; border-radius:12px; padding:16px}
    .k{color:#555}
  </style>
</head>
<body>
  <h1>Capture Report</h1>
  <div class="card">
    <div><span class="k">Generated:</span> %s</div>
    <div><span class="k">Input:</span> <code>%s</code></div>
    <div><span class="k">TCP ports:</span> %v</div>
    <div><span class="k">UDP ports:</span> %v</div>
  </div>

  <h2>Summary</h2>
  <div class="grid">
    <div class="card">
      <div><span class="k">Packets:</span> %d</div>
      <div><span class="k">Payload bytes:</span> %d</div>
      <div><span class="k">Entropy:</span> %.4f bits/byte</div>
      <div><span class="k">ASCII ratio:</span> %.4f</div>
      <div><span class="k">Start:</span> %s</div>
      <div><span class="k">End:</span> %s</div>
    </div>
    <div class="card">
      <div class="k">Payload size histogram (log2 bins)</div>
      <pre>%s</pre>
    </div>
    <div class="card">
      <div class="k">Inter-arrival histogram (ms, log2 bins)</div>
      <pre>%s</pre>
    </div>
  </div>
</body>
</html>
`,
		r.GeneratedAt.Format(time.RFC3339),
		r.Input,
		r.TCPPorts,
		r.UDPPorts,
		r.Packets,
		r.Bytes,
		r.Entropy,
		r.ASCIIRatio,
		r.Start.Format(time.RFC3339Nano),
		r.End.Format(time.RFC3339Nano),
		escapePre(renderHist(r.SizeBinsLog2)),
		escapePre(renderHist(r.InterArrivalMsBins)),
	)
}

func escapePre(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func renderHist(m map[int]int) string {
	if len(m) == 0 {
		return "(empty)"
	}
	keys := make([]int, 0, len(m))
	max := 0
	for k, v := range m {
		keys = append(keys, k)
		if v > max {
			max = v
		}
	}
	sort.Ints(keys)
	var b strings.Builder
	for _, k := range keys {
		v := m[k]
		barLen := 0
		if max > 0 {
			barLen = int(float64(v) / float64(max) * 40)
		}
		b.WriteString(fmt.Sprintf("%2d | %8d | %s\n", k, v, strings.Repeat("█", barLen)))
	}
	return b.String()
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
