//go:build pcap

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	var (
		iface   = flag.String("iface", "", "capture interface (e.g. en0)")
		outPath = flag.String("out", "capture.pcap", "output pcap path")
		filter  = flag.String("filter", "", "BPF filter (required)")
		snaplen = flag.Int("snaplen", 262144, "snaplen")
		promisc = flag.Bool("promisc", false, "promiscuous mode")
		dur     = flag.Duration("duration", 0, "capture duration (0 = until Ctrl-C)")
	)
	flag.Parse()
	if *iface == "" {
		fatal(fmt.Errorf("-iface is required"))
	}
	if *filter == "" {
		fatal(fmt.Errorf("-filter is required"))
	}

	handle, err := pcap.OpenLive(*iface, int32(*snaplen), *promisc, pcap.BlockForever)
	if err != nil {
		fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(*filter); err != nil {
		fatal(err)
	}

	f, err := os.Create(*outPath)
	if err != nil {
		fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(*snaplen), handle.LinkType()); err != nil {
		fatal(err)
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	var timer <-chan time.Time
	if *dur > 0 {
		timer = time.After(*dur)
	}

	for {
		select {
		case <-sig:
			return
		case <-timer:
			return
		case pkt, ok := <-src.Packets():
			if !ok {
				return
			}
			ci := pkt.Metadata().CaptureInfo
			if err := w.WritePacket(ci, pkt.Data()); err != nil {
				fatal(err)
			}
		}
	}
}

func fatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
