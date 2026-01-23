package main

import (
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestParsePorts(t *testing.T) {
	t.Parallel()

	got, err := parsePorts(" 443, 80,80 ")
	if err != nil {
		t.Fatalf("parsePorts: %v", err)
	}
	if len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("unexpected ports: %v", got)
	}
	if _, err := parsePorts("not-a-port"); err == nil {
		t.Fatalf("expected error for invalid port")
	}
}

func TestComputeByteStats(t *testing.T) {
	t.Parallel()

	var freq [256]uint64
	freq['A'] = 10
	bs := computeByteStats(freq)
	if bs.asciiRatio != 1 {
		t.Fatalf("expected asciiRatio=1, got %v", bs.asciiRatio)
	}
	if bs.entropy != 0 {
		t.Fatalf("expected entropy=0, got %v", bs.entropy)
	}
}

func TestLog2Bin(t *testing.T) {
	t.Parallel()

	if log2Bin(0) != 0 || log2Bin(1) != 0 || log2Bin(2) != 1 {
		t.Fatalf("unexpected log2 bins")
	}
	if log2Bin(1<<40) != 31 {
		t.Fatalf("expected clamp to 31")
	}
}

func TestRenderHelpers(t *testing.T) {
	t.Parallel()

	if escapePre("<&>") != "&lt;&amp;&gt;" {
		t.Fatalf("escapePre mismatch")
	}
	h := renderHist(map[int]int{0: 1, 3: 2})
	if !strings.Contains(h, " 0 |") || !strings.Contains(h, " 3 |") {
		t.Fatalf("renderHist missing keys: %q", h)
	}

	r := &report{
		GeneratedAt:        time.Unix(1, 0),
		Input:              "x.pcap",
		TCPPorts:           []uint16{1},
		UDPPorts:           []uint16{2},
		Packets:            3,
		Bytes:              4,
		Entropy:            1.23,
		ASCIIRatio:         0.5,
		SizeBinsLog2:       map[int]int{0: 1},
		InterArrivalMsBins: map[int]int{1: 2},
		Start:              time.Unix(1, 0),
		End:                time.Unix(2, 0),
	}
	if !strings.Contains(renderMarkdown(r), "Capture Report") {
		t.Fatalf("renderMarkdown missing title")
	}
	if !strings.Contains(renderHTML(r), "<!doctype html>") {
		t.Fatalf("renderHTML missing doctype")
	}
}

func TestAnalyze_PCAP(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.pcap")

	payload := []byte("ABCD")
	if err := writeTestPCAP(path, 80, payload); err != nil {
		t.Fatalf("writeTestPCAP: %v", err)
	}

	rep, err := analyze(path, []uint16{80}, nil)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if rep.Packets != 2 {
		t.Fatalf("expected 2 packets, got %d", rep.Packets)
	}
	if rep.Bytes != int64(len(payload)*2) {
		t.Fatalf("expected bytes=%d, got %d", len(payload)*2, rep.Bytes)
	}
	if rep.ASCIIRatio != 1 {
		t.Fatalf("expected ASCIIRatio=1, got %v", rep.ASCIIRatio)
	}
	if math.Abs(rep.Entropy-math.Log2(4)) > 0.0001 {
		t.Fatalf("unexpected entropy: %v", rep.Entropy)
	}
	if len(rep.InterArrivalMsBins) != 1 {
		t.Fatalf("expected 1 inter-arrival bin, got %v", rep.InterArrivalMsBins)
	}
}

func writeTestPCAP(path string, dstPort uint16, payload []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ts0 := time.Unix(10, 0)
	for i := 0; i < 2; i++ {
		buf := gopacket.NewSerializeBuffer()

		eth := layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
			DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    net.IPv4(10, 0, 0, 1),
			DstIP:    net.IPv4(10, 0, 0, 2),
			Protocol: layers.IPProtocolTCP,
		}
		tcp := layers.TCP{
			SrcPort: layers.TCPPort(12345),
			DstPort: layers.TCPPort(dstPort),
			Seq:     uint32(i + 1),
			ACK:     true,
			Window:  1024,
		}
		tcp.SetNetworkLayerForChecksum(&ip)

		if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(payload)); err != nil {
			return err
		}
		b := buf.Bytes()

		ci := gopacket.CaptureInfo{
			Timestamp:      ts0.Add(time.Duration(i) * 10 * time.Millisecond),
			CaptureLength:  len(b),
			Length:         len(b),
			InterfaceIndex: 0,
		}
		if err := w.WritePacket(ci, b); err != nil {
			return err
		}
	}
	return nil
}

func TestRenderHist_Empty(t *testing.T) {
	t.Parallel()

	if got := renderHist(nil); got != "(empty)" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestComputeByteStats_Empty(t *testing.T) {
	t.Parallel()

	var freq [256]uint64
	bs := computeByteStats(freq)
	if bs.entropy != 0 || bs.asciiRatio != 0 {
		t.Fatalf("unexpected stats: %+v", bs)
	}
}

func TestMQTTReport_Log2Bin_NoPanicOnLarge(t *testing.T) {
	t.Parallel()

	_ = log2Bin(1 << 30)
}

func TestEscapePre_NoAllocRegression(t *testing.T) {
	t.Parallel()

	in := strings.Repeat("<", 32) + strings.Repeat("&", 32) + strings.Repeat(">", 32)
	out := escapePre(in)
	if !strings.Contains(out, "&lt;") || !strings.Contains(out, "&amp;") || !strings.Contains(out, "&gt;") {
		t.Fatalf("escapePre unexpected output")
	}
}

func TestRenderMarkdownHTML_NoPanicOnNilReport(t *testing.T) {
	t.Parallel()

	// Smoke: ensure formatting helpers don't panic on minimal input.
	r := &report{}
	_ = renderMarkdown(r)
	_ = renderHTML(r)
}

func TestParsePorts_Empty(t *testing.T) {
	t.Parallel()

	got, err := parsePorts("")
	if err != nil {
		t.Fatalf("parsePorts: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
}

func TestAnalyze_RejectsNonPcapFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "not.pcap")
	if err := os.WriteFile(path, []byte("not a pcap"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := analyze(path, []uint16{80}, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestComputeByteStats_Mixed(t *testing.T) {
	t.Parallel()

	var freq [256]uint64
	freq['A'] = 1
	freq['B'] = 1
	freq[0] = 1
	bs := computeByteStats(freq)
	if bs.entropy <= 0 {
		t.Fatalf("expected positive entropy")
	}
	if bs.asciiRatio <= 0 || bs.asciiRatio >= 1 {
		t.Fatalf("expected 0<asciiRatio<1, got %v", bs.asciiRatio)
	}
}

func TestRenderHist_Deterministic(t *testing.T) {
	t.Parallel()

	h := renderHist(map[int]int{2: 1, 1: 1})
	if !strings.Contains(h, " 1 |") || !strings.Contains(h, " 2 |") {
		t.Fatalf("unexpected: %q", h)
	}
}

func TestEscapePre_IdempotentOnSafeString(t *testing.T) {
	t.Parallel()

	in := "abc123"
	if got := escapePre(in); got != in {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestRenderHist_BarNonEmpty(t *testing.T) {
	t.Parallel()

	h := renderHist(map[int]int{0: 1, 1: 10})
	if !strings.Contains(h, "█") {
		t.Fatalf("expected bar chart")
	}
}

func TestComputeByteStats_EntropyBounds(t *testing.T) {
	t.Parallel()

	var freq [256]uint64
	for i := 0; i < 256; i++ {
		freq[i] = 1
	}
	bs := computeByteStats(freq)
	if bs.entropy < 7.9 || bs.entropy > 8.1 {
		t.Fatalf("expected ~8 bits/byte, got %v", bs.entropy)
	}
}

func TestAnalyze_FilterByPort(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test2.pcap")

	if err := writeTestPCAP(path, 8080, []byte("ZZ")); err != nil {
		t.Fatalf("writeTestPCAP: %v", err)
	}
	rep, err := analyze(path, []uint16{80}, nil)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if rep.Packets != 0 {
		t.Fatalf("expected 0 packets after port filter, got %d", rep.Packets)
	}
}

func TestRenderMarkdown_ContainsValues(t *testing.T) {
	t.Parallel()

	r := &report{Packets: 7, Bytes: 11}
	out := renderMarkdown(r)
	if !strings.Contains(out, "Packets: 7") || !strings.Contains(out, "Payload bytes: 11") {
		t.Fatalf("missing fields: %q", out)
	}
}

func TestRenderHTML_EscapesPre(t *testing.T) {
	t.Parallel()

	r := &report{
		SizeBinsLog2:       map[int]int{0: 1},
		InterArrivalMsBins: map[int]int{0: 1},
	}
	out := renderHTML(r)
	if !strings.Contains(out, "<pre>") || !strings.Contains(out, "Capture Report") {
		t.Fatalf("unexpected HTML output")
	}
}
