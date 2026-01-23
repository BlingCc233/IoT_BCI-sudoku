# Capture Tool & Report

Tools:

- `cmd/iotbci-capture`: live capture (optional build tag), save pcap
- `cmd/iotbci-report`: offline analysis + HTML/Markdown report

Reports include:

- Packet/segment size histogram
- Inter-arrival time histogram
- Byte entropy and ASCII ratio over time
- Total TCP/UDP payload bytes (for overhead computation with known application payload bytes)

## 1) Live capture（仅抓指定端口）

`iotbci-capture` 依赖 libpcap，因此默认不编译，需要加 build tag：

```bash
go run -tags pcap ./cmd/iotbci-capture \
  -iface en0 \
  -out capture.pcap \
  -filter "tcp port 12345 or udp port 5684" \
  -duration 30s
```

注意：
- 需要足够权限（macOS/Linux 上可能需要 sudo）。
- `-filter` 为 BPF 表达式，可精确到协议/端口/host。

## 2) 离线报告（论文可用的量化指标）

```bash
go run ./cmd/iotbci-report \
  -in capture.pcap \
  -out_dir report_out \
  -tcp_ports 12345 \
  -udp_ports 5684
```

输出：

- `report_out/report.json`
- `report_out/report.md`
- `report_out/report.html`

目前统计基于 TCP/UDP 的 payload 字节（不含 L2/L3/L4 头），更贴近“外观层/加密层”实际暴露的可侧写信息。

## 3) 一键证据集（推荐）

`cmd/iotbci-evidence` 可选自动调用抓包与报告工具，为 DTLS/MQTT/CoAP/纯 AEAD/IoT_BCI-sudoku 生成分协议抓包报告：

```bash
go run ./cmd/iotbci-evidence -out_dir evidence_out -messages 200 -size 256 -timeout 30s -capture_iface lo0
```
