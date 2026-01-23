# IoT_BCI-sudoku

Sudoku is an IoT BCI (brain-computer interface) LAN communication protocol that provides:

- A Sudoku-inspired ASCII/entropy traffic appearance layer (arbitrary padding + layout rotation)
- AEAD encryption (AES-128-GCM / ChaCha20-Poly1305 / none)
- Secure handshake with anti-replay and identity verification (Ed25519)
- Mux (multiple logical streams over one session)
- UoT (UDP-over-TCP) for datagram-style workloads
- Suspicious-traffic fallback hooks (decoy / do-not-reveal)
- Benchmark & comparison harness (DTLS / MQTT / CoAP / pure AEAD)
- Capture & report tools for thesis-grade quantitative evidence

## Docs

Start here: `doc/INDEX.md`

Public Go API: `apis/README.md`

## Quickstart

- Run micro-benchmarks: `go run ./cmd/iotbci-bench -messages 1000 -size 256 -timeout 30s -out bench.json`
- Run thesis-style evidence (loopback TCP/UDP + optional pcap capture/report): `go run ./cmd/iotbci-evidence -out_dir evidence_out -messages 200 -size 256 -timeout 30s`
- Run protocol (loopback dev configs):
  - Server: `go run ./cmd/iotbci -c configs/dev_server_stream.json -timeout 30s`
  - Client: `go run ./cmd/iotbci -c configs/dev_client_stream.json -timeout 30s`
- Live capture (requires libpcap): `go run -tags pcap ./cmd/iotbci-capture -iface lo0 -out capture.pcap -filter "tcp port 9000"`
- Offline report: `go run ./cmd/iotbci-report -in capture.pcap -out_dir report_out -tcp_ports 9000`
