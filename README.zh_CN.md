# IoT_BCI-sudoku

`IoT_BCI-sudoku` 是面向局域网脑机接口（BCI）通信的 Sudoku 协议重构实现，目标是：

- 保留 Sudoku 外观层（ASCII/熵偏好、任意 padding、布局轮转、下行带宽优化）
- 保留并增强安全能力（Ed25519 身份校验、时间戳握手、私钥哈希用户匹配、抗重放/MITM 工程落地）
- 保留 UoT（UDP-over-TCP）与 mux（多路复用）
- 对异常/可疑流量进行记录与回落（不会返回真实数据）
- 提供可复现的对比基线与抓包报告工具，支撑论文量化指标

入口文档：`doc/INDEX.md`

公开 Go API：`apis/README.md`

## 快速开始

- 运行内置 micro-bench（输出 JSON）：`go run ./cmd/iotbci-bench -messages 1000 -size 256 -timeout 30s -out bench.json`
- 运行论文证据集（回环 TCP/UDP + 可选 pcap 抓包/报告）：`go run ./cmd/iotbci-evidence -out_dir evidence_out -messages 200 -size 256 -timeout 30s`
- 攻击模拟（重放 / MITM 篡改 / 探测洪泛）：`go run ./cmd/iotbci-attack -timeout 10s -out attack_report.json`
- 统一可视化（bench/evidence/attack 一页查看）：`go run ./cmd/iotbci-dashboard -bench bench.json -evidence evidence_out/evidence.json -attack attack_report.json -out_dir dashboard_out`
- LaTeX 图表/表格生成：`go run ./cmd/iotbci-texgen -bench bench.json -out_dir tex/generated`
- 运行协议（本机回环测试）：
  - 服务端：`go run ./cmd/iotbci -c configs/dev_server_stream.json -timeout 30s`
  - 客户端：`go run ./cmd/iotbci -c configs/dev_client_stream.json -timeout 30s`
- 抓包（需要 libpcap）：`go run -tags pcap ./cmd/iotbci-capture -iface lo0 -out capture.pcap -filter "tcp port 9000"`
- 报告：`go run ./cmd/iotbci-report -in capture.pcap -out_dir report_out -tcp_ports 9000`
