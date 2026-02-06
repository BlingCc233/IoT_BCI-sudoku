# Benchmarks & Comparisons

This repo ships a reproducible comparison harness that can emit:

- Peak RAM usage (best-effort via `runtime.MemStats`)
- Core library code size (source bytes)
- Per-message processing latency (encode/decode + crypto)
- Added byte ratio (encoding/padding/rotation overhead)
- Appearance metrics: length distribution, timing hints, entropy, ASCII ratio

Baselines:

- DTLS (certificate/ECDHE)
- MQTT over TLS
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
- `wire_write_calls` / `wire_read_calls`：线上读写调用次数（外观/实现细节提示）
- `wire_write_size_bins_log2`：写入尺寸分布（log2 bins，外观特征：长度）
- `wire_write_interarrival_ms_bins_log2`：写入间隔分布（ms，log2 bins，外观特征：时序）
- `wire_write_size_seq_sample` / `wire_write_interarrival_ms_seq_sample`：长度/间隔序列样本（用于协议指纹与侧写分类）
- `wire_active_duration_ms`：首写到末写的活跃区间（ms）
- `wire_entropy` / `wire_ascii_ratio`：对“线上 payload 字节”计算的外观指标
- `peak_*`：峰值内存（采样近似，论文需注明采样方法与误差来源）
- `payload_throughput_bps` / `wire_throughput_bps`：吞吐（bytes/s，按 `duration_ms` 计算）

当前 bench 默认包含：

- `iotbci-sudoku-pure`（纯数独：ASCII 外观优先；默认关闭 padding 以降低延迟/CPU，展示吞吐/时延上限）
- `iotbci-sudoku-packed`（双向 6-bit packed：启用 `EnablePackedUplink`；默认关闭 padding 以展示吞吐/时延上限）
- `pure-aead`（无数独外观层的 AEAD record，对比基线）
- `dtls-ecdhe-ecdsa-aes256cbc`
- `mqtt-3.1.1-qos0-tls`
- `coap-udp`

注意：`iotbci-sudoku-*` 与 `pure-aead` 的 micro-bench 默认使用 `net.Pipe`（尽量隔离内核网络栈噪声），而 DTLS/MQTT/CoAP 需要真实 UDP/TCP socket，因此会包含更多 OS 网络栈开销。论文对比建议以 `cmd/iotbci-evidence` 的“真实回环流量”数据为主，以 `cmd/iotbci-bench` 的 micro-bench 作为补充。

## 论文证据集（推荐）

`cmd/iotbci-evidence` 会在本机回环上运行所有协议对比场景，并可选自动调用 `cmd/iotbci-capture` + `cmd/iotbci-report` 生成每个协议的抓包报告：

```bash
go run ./cmd/iotbci-evidence -out_dir evidence_out -messages 200 -size 256 -timeout 30s
```

侧写评估可通过以下参数打开 Sudoku padding（默认 0/0）：

```bash
go run ./cmd/iotbci-evidence \
  -out_dir evidence_out \
  -messages 200 -size 256 -timeout 30s \
  -sudoku_padding_min 20 -sudoku_padding_max 45
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
