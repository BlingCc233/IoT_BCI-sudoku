# 07_cross_region_benchmark

跨国网络真实环境基准（本机 client + VPS server），覆盖：
- `iotbci-sudoku-pure-tcp`
- `iotbci-sudoku-packed-tcp`
- `pure-aead-tcp`
- `dtls-psk-aes128gcm`
- `coap-udp`
- `mqtt-3.1.1-qos0-tls`

## 特别说明（UDP 受限）
本脚本支持两种路径：
- TCP 协议（Sudoku/Pure-AEAD/MQTT）：直接连 VPS 公网端口。
- UDP 协议（DTLS/CoAP）：若 VPS 公网 UDP 被安全组限制，自动采用“本地 UDP -> TCP relay -> VPS 回环 UDP”中继路径。

该中继会引入额外开销，脚本会在 `summary.json` 中标注 `transport_note`。

## 依赖
本机：
- Go 1.23+
- Python 3.9+
- `expect`
- `socat`

VPS：
- 已部署本仓库并可执行 `/root/IoT_BCI-sudoku/iotbci-netbench`
- `socat`

## 运行
```bash
python3 evidence_steps/07_cross_region_benchmark/run.py \
  --host 8.219.204.112 \
  --user root \
  --password 'kevin715041@' \
  --runs 3 \
  --messages 80 \
  --size 256
```

输出：
- `out/summary.json`
- `out/summary.txt`
- `out/report.html`
- `out/runs/r*/<proto>_{client,server}.json`
