# Documentation Index

This folder contains the complete protocol spec, threat model, engineering notes, and reproducible benchmark/capture workflows.

- Start with: `doc/USER_GUIDE.md` (how to read/use/reproduce everything)

- `doc/SPEC.md`
- `doc/HANDSHAKE.md`
- `doc/STATE_MACHINE.md`
- `doc/SECURITY.md`
- `doc/OBFS_SUDOKU.md`
- `doc/FALLBACK.md`
- `doc/BENCHMARKS.md`
- `doc/CAPTURE.md`
- `doc/DEPLOYMENT.md`

## Quickstart

- 运行单机 micro-bench（输出 JSON）：`go run ./cmd/iotbci-bench -messages 1000 -size 256 -timeout 30s -out bench.json`
- 运行论文证据集（回环 TCP/UDP + 可选抓包/报告）：`go run ./cmd/iotbci-evidence -out_dir evidence_out -messages 200 -size 256 -timeout 30s`
- 生成抓包报告：
  - 抓包（需要 libpcap）：`go run -tags pcap ./cmd/iotbci-capture ...`
  - 报告：`go run ./cmd/iotbci-report -in capture.pcap -tcp_ports ... -udp_ports ... -out_dir report_out`
