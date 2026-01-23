# Benchmarks & Comparisons

This repo ships a reproducible comparison harness that can emit:

- Peak RAM usage (best-effort via `runtime.MemStats`)
- Core library code size (source bytes)
- Per-message processing latency (encode/decode + crypto)
- Added byte ratio (encoding/padding/rotation overhead)
- Appearance metrics: length distribution, timing hints, entropy, ASCII ratio

Baselines:

- DTLS
- MQTT
- CoAP
- Pure AEAD framing (no Sudoku appearance)

## 快速开始（当前已实现）

运行本仓库内置 bench（输出 JSON）：

```bash
go run ./cmd/iotbci-bench -messages 1000 -size 256 -timeout 30s -out bench.json
```

输出字段：

- `core_source_bytes`：核心库源码体积（`pkg/iotbci` + `pkg/obfs/sudoku`，不含测试）
- `overhead_ratio`：`wire_bytes_total / payload_bytes_total`
- `avg_rtt_ms` / `p95_rtt_ms`：单次收发处理延迟（使用 `net.Pipe`，主要反映编码/解码/加密的 CPU 开销）
- `wire_entropy` / `wire_ascii_ratio`：对“线上 payload 字节”计算的外观指标
- `peak_*`：峰值内存（采样近似，论文需注明采样方法与误差来源）

当前 bench 默认包含：

- `iotbci-sudoku-pure`（纯数独下行）
- `iotbci-sudoku-packed`（下行 6-bit packed 优化）
- `pure-aead`（无数独外观层的 AEAD record，对比基线）
- `dtls-psk-aes128gcm`
- `mqtt-3.1.1-qos0`
- `coap-udp`

注意：`iotbci-sudoku-*` 与 `pure-aead` 的 micro-bench 默认使用 `net.Pipe`（尽量隔离内核网络栈噪声），而 DTLS/MQTT/CoAP 需要真实 UDP/TCP socket，因此会包含更多 OS 网络栈开销。论文对比建议以 `cmd/iotbci-evidence` 的“真实回环流量”数据为主，以 `cmd/iotbci-bench` 的 micro-bench 作为补充。

## 论文证据集（推荐）

`cmd/iotbci-evidence` 会在本机回环上运行所有协议对比场景，并可选自动调用 `cmd/iotbci-capture` + `cmd/iotbci-report` 生成每个协议的抓包报告：

```bash
go run ./cmd/iotbci-evidence -out_dir evidence_out -messages 200 -size 256 -timeout 30s
```

启用抓包（需要 libpcap + 权限）：

```bash
go run ./cmd/iotbci-evidence -out_dir evidence_out -messages 200 -size 256 -timeout 30s -capture_iface lo0
```

输出：

- `evidence_out/evidence.json`（总览）
- `evidence_out/<scenario>/metrics.json`
- `evidence_out/<scenario>/capture.pcap`（可选）
- `evidence_out/<scenario>/pcap_report/report.{json,md,html}`（可选）
