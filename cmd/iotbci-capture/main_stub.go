//go:build !pcap

package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "iotbci-capture: live capture requires build tag 'pcap' (libpcap).")
	_, _ = fmt.Fprintln(os.Stderr, "Example: go run -tags pcap ./cmd/iotbci-capture -iface en0 -out capture.pcap -filter \"tcp port 12345\"")
	os.Exit(2)
}
