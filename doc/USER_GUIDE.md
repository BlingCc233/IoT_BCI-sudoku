# IoT_BCI-sudoku 使用手册（阅读顺序 / 复现 / 使用 / 扩展）

本手册的目标：

1. 让你能“按顺序读懂”仓库：从文档到代码，从入口到核心层，再到工具链与对比评估。
2. 让评审/答辩可以“一键复现”：编译、运行、抓包、生成报告、输出论文指标。
3. 让后续扩展可控：知道每个模块的边界、调用关系、状态机、关键安全点、资源上限点。

如果你只想快速跑通，请先看「快速开始」。如果你想系统理解与 review，请看「推荐阅读顺序」和「代码导览」。

---

## 0. 快速开始（5 分钟跑通）

### 0.1 环境要求

- Go：`1.23.x`（见 `go.mod` / CI）
- 可选抓包：需要 libpcap（macOS/Linux 通常需要额外安装）：
  - 只影响 `cmd/iotbci-capture`（默认 stub，不带 `pcap` tag 不会编译抓包实现）
  - `cmd/iotbci-report` 不依赖 libpcap（解析 pcap/pcapng）

### 0.2 运行协议（本机回环 dev 配置）

开两个终端：

1) 启动 server（stream/mux/uot 三选一）：

```bash
go run ./cmd/iotbci -c configs/dev_server_stream.json -timeout 30s
# 或
go run ./cmd/iotbci -c configs/dev_server_mux.json -timeout 30s
# 或
go run ./cmd/iotbci -c configs/dev_server_uot.json -timeout 30s
```

2) 启动 client（对应 app）：

```bash
go run ./cmd/iotbci -c configs/dev_client_stream.json -timeout 30s
# 或
go run ./cmd/iotbci -c configs/dev_client_mux.json -timeout 30s
# 或
go run ./cmd/iotbci -c configs/dev_client_uot.json -timeout 30s
```

预期行为：client 会根据 `bci` 配置生成 BCI 帧并做 echo 校验（哈希一致即通过）。

### 0.3 运行对比基线与论文证据集

- micro-bench（主要反映编解码/加密开销，输出 JSON）：

```bash
go run ./cmd/iotbci-bench -messages 1000 -size 256 -timeout 30s -out bench.json
```

- 论文证据集（真实回环 socket，含 DTLS/MQTT/CoAP/纯 AEAD/IoTBCI-Sudoku；输出目录）：

```bash
go run ./cmd/iotbci-evidence -out_dir evidence_out -messages 200 -size 256 -timeout 30s
```

输出：`evidence_out/evidence.json` + 每个场景 `evidence_out/<scenario>/metrics.json`

### 0.4 可选：抓包 + 报告（只抓指定端口流量）

1) 启用 evidence 的自动抓包（需要 libpcap + 权限）：

```bash
go run ./cmd/iotbci-evidence -out_dir evidence_out -messages 200 -size 256 -timeout 30s -capture_iface lo0
```

2) 或手动抓包（示例：抓本机 9000 端口 TCP）：

```bash
go run -tags pcap ./cmd/iotbci-capture -iface lo0 -out capture.pcap -filter "tcp port 9000" -duration 30s
go run ./cmd/iotbci-report -in capture.pcap -out_dir report_out -tcp_ports 9000
```

输出：`report_out/report.{json,md,html}`

---

## 1. 推荐阅读顺序（文档 -> 代码）

### 1.1 文档阅读顺序（建议）

1) `doc/INDEX.md`：文档索引与复现入口  
2) `doc/SPEC.md`：封装格式与字段定义（看“协议长什么样”）  
3) `doc/HANDSHAKE.md`：握手流程（抗重放/MITM 的工程落地）  
4) `doc/STATE_MACHINE.md`：整体状态机（异常、回落、关闭语义）  
5) `doc/SECURITY.md`：威胁模型与应对、参数选择建议  
6) `doc/OBFS_SUDOKU.md`：数独外观层（padding/轮转/可解析性）  
7) `doc/FALLBACK.md`：异常流量回落/沉默策略  
8) `doc/BENCHMARKS.md` + `doc/CAPTURE.md`：论文级对比与抓包报告  
9) `doc/DEPLOYMENT.md`：密钥/证书/吊销与跨平台构建

### 1.2 代码阅读顺序（从入口到核心）

建议按“可执行入口 -> 节点 glue -> 核心协议库 -> 外观层 -> 工具链”来读：

1) `cmd/iotbci/main.go`：读取 config，选择 server/client  
2) `internal/node/config.go`：JSON 配置字段 -> `iotbci.{Client,Server}Options`  
3) `internal/node/serve.go`：`Serve` / `DialAndRun` 的端到端行为（stream/mux/uot 三种 app）  
4) `pkg/iotbci/handshake_{client,server}.go`：协议握手（认证/抗重放/派生会话密钥）  
5) `pkg/iotbci/recordconn.go`：record AEAD（可选）  
6) `pkg/iotbci/obfs_conn.go` + `pkg/obfs/sudoku/*`：数独外观层与下行 packed 优化  
7) `pkg/iotbci/frame/frame.go`：stream app 的帧封装（4 字节长度前缀）  
8) `pkg/iotbci/mux/*`：多路复用（多逻辑流）  
9) `pkg/iotbci/uot/*`：UoT（UDP-over-TCP）  
10) `internal/bench/*` + `cmd/iotbci-{bench,evidence}`：对比基线与证据集生成  
11) `cmd/iotbci-{capture,report}`：抓包与报告

---

## 2. 仓库结构与模块边界

### 2.1 目录说明

- `pkg/iotbci`：核心协议库（握手/安全/record AEAD/选项/错误）
- `pkg/obfs/sudoku`：数独外观层（table/布局/轮转/随机填充/可解析封装）
- `pkg/iotbci/frame`：stream 模式的帧封装（长度前缀）
- `pkg/iotbci/mux`：复用层（多 stream）
- `pkg/iotbci/uot`：UoT（datagram over stream）
- `internal/node`：可执行节点 glue（配置解析、server/client 逻辑、fallback 处理）
- `internal/bci`：BCI 数据生成器（可复现实验数据）
- `internal/bench`：DTLS/MQTT/CoAP/纯 AEAD 与 IoTBCI-Sudoku 的对比跑分实现
- `cmd/*`：可执行工具入口
- `configs/*.json`：可运行的示例配置
- `doc/*`：协议规范与工程说明
- `apis/*`：对外稳定 API（推荐用于集成）

### 2.2 协议分层（强烈建议先建立这个心智模型）

本协议在 TCP 上叠加多层（可选项用括号标注）：

```
            ┌──────────────────────────────────────┐
            │              App Layer               │
            │  stream(frame) / mux / uot(packet)   │
            └──────────────────────────────────────┘
            ┌──────────────────────────────────────┐
            │         Session Record (optional)    │
            │  AEAD record over obfsConn           │
            └──────────────────────────────────────┘
            ┌──────────────────────────────────────┐
            │       Sudoku Obfuscation Layer       │
            │  uplink: sudoku.Conn                 │
            │  downlink: sudoku.PackedConn (opt)   │
            └──────────────────────────────────────┘
            ┌──────────────────────────────────────┐
            │                TCP                   │
            └──────────────────────────────────────┘
```

握手阶段还会额外引入一个“握手 channel”（可选 PSK-AEAD）：

- 目的：抗主动探测（没有 PSK 无法正确解密/解析握手帧）、让握手数据也能隐藏在数独外观层下
- 实现：`handshake_{client,server}.go` 里先建 `obfsConn`，再按 `HandshakeAEAD` 包一层 `recordConn`

---

## 3. 协议端到端流程（函数交互关系）

### 3.1 Server 侧主路径（从 Accept 到返回 session）

入口：`internal/node/Serve`（或你在业务里直接用 `apis.ServerHandshake`）

关键调用链（简化）：

1) `Serve` / `serveLoop`：`ln.Accept()` 得到 `raw net.Conn`
2) `iotbci.ServerHandshake(ctx, raw, opts)`：
   - `selectTableByProbe(...)`：从 `bufio.Reader` 里探测选择正确的 Sudoku table（多 table 轮转时用于无歧义解码）
   - `buildObfsConnForServer(...)`：
     - uplink 使用 `sudoku.Conn`（可录制 pre-read 字节用于回落）
     - downlink 可选 `sudoku.PackedConn`（带宽优化）
   - （可选）握手 AEAD：`NewRecordConn(obfsConn, HandshakeAEAD, ...)`
   - 读 `ClientHello`：验证时间戳 `TimeSkew`、选项一致性、证书/签名
   - 抗重放：`ReplayCache.SeenOrAdd(token, now)`（认证后才 commit）
   - 生成 `ServerHello`：X25519 临时密钥，签名，回显 nonce
   - 计算会话密钥：HKDF + transcript hash
   - 读 `ClientFinish`：验证 MAC（证明双方拥有共享密钥）
   - 切换到会话 record：`NewRecordConn(obfsConn, SessionAEAD, ...)`（可选）
3) 返回 `net.Conn`（session）给上层 app（stream/mux/uot）

错误与回落：

- 探测/握手中出现异常会返回 `*iotbci.SuspiciousError`
- 该 error 附带一个“带缓冲/录制数据”的 `Conn`，用于 `internal/node/HandleSuspicious` 做 fallback/silent（见 `doc/FALLBACK.md`）

### 3.2 Client 侧主路径

入口：`internal/node/DialAndRun`（或 `apis.Dial` / `apis.DialMux` / `apis.DialUoT`）

关键调用链（简化）：

1) `DialAndRun`：`net.DialTimeout("tcp", server)`
2) `iotbci.ClientHandshake(ctx, raw, opts)`：
   - 根据 `custom_tables` 随机选一个 table（如果配置了多个）
   - `buildObfsConnForClient`：uplink sudoku + （可选）downlink packed
   - （可选）握手 record：PSK AEAD
   - 写 `ClientHello`（含 timestamp / nonce / userHash / clientEphPub / cert / signature）
   - 读 `ServerHello`：验证回显 nonce / 签名 / 选项一致性 / timestamp
   - 派生会话密钥，发送 `ClientFinish`（MAC）
   - 切换到会话 record（可选）
3) 返回 `net.Conn` 给上层 app

---

## 4. 状态机（读代码时的“地图”）

完整状态机：`doc/STATE_MACHINE.md`

读代码时建议把状态分成 3 段：

1) **Probe/Obfs 建立阶段**：选择 table、确定 downlink 模式、为 fallback 录制 pre-read 数据  
2) **Handshake 阶段**：ClientHello -> ServerHello -> ClientFinish（认证 + 抗重放 + 会话密钥派生）  
3) **Session 阶段**：进入 stream/mux/uot 其中一种应用模式，直到 Close/异常

在代码里最重要的“状态边界”：

- `selectTableByProbe(...)` 成功/失败（失败即 Suspicious）
- `ClientHello` 校验通过后才会 `ReplayCache.SeenOrAdd(...)`（避免 DoS 填满缓存）
- `ClientFinish` 校验通过后才 `StopRecording()`（避免把真实握手数据泄露到 fallback）

---

## 5. 配置文件怎么写（JSON 字段逐项解释）

示例配置：`configs/dev_*.json`

配置结构由 `internal/node/config.go` 定义，核心字段如下：

### 5.1 顶层字段

- `mode`：`"server"` 或 `"client"`
- `listen`：server 监听地址（如 `"0.0.0.0:9000"`）
- `server`：client 连接地址（如 `"192.168.1.10:9000"`）
- `app`：`"stream" | "mux" | "uot"`

### 5.2 `obfs`（数独外观层）

- `ascii`：`"prefer_ascii"` 或 `"prefer_entropy"`（外观偏好）
- `custom_tables`：table 轮转集合，元素为 8 字符模式，要求**语义修正后的**：
  - `x`：冗余 bit（2 个）
  - `p`：4-bit position（4 个）
  - `v`：2-bit value（2 个）
  - 每个 pattern 必须恰好包含 `2x + 4p + 2v`，例如 `"xppppxvv"`, `"vppxppvx"`
- `padding_min` / `padding_max`：0..100（百分比），每连接会在范围内采样 padding 率
- `enable_pure_downlink`：
  - `true`：下行也用纯数独外观（更一致但更费带宽）
  - `false`：下行使用 6-bit packed（更省带宽，推荐配合 AEAD）

### 5.3 `security`（握手/会话安全）

- `psk`：
  - 若 `handshake_aead != "none"` 则必填（握手抗主动探测）
  - 若 `obfs.key` 为空，会自动用 `psk` 作为 obfs seed
- `handshake_aead`：`"none" | "aes-128-gcm" | "chacha20-poly1305"`
- `session_aead`：同上（会话 record AEAD）
- `handshake_timeout_sec`：握手总超时（建议 2~5s）
- `time_skew_sec`：允许的时间偏移（LAN 建议 30~120s）
- `replay_window_sec` / `replay_cache_size`：仅 server 用于抗重放窗口（见 `doc/SECURITY.md`）
- `max_handshake_size`：单条握手消息 body 上限（建议 4~16KB）

### 5.4 `identity`（身份/证书）

- `master_public_key_hex`：master 公钥（32 字节 hex），用于验证对端证书签名
- `peer_public_key_hex`：可选 pin（无需 master CA 时使用）
- `local_private_key_hex`：本地 Ed25519 私钥（支持 32 字节 seed 或 64 字节 private key 的 hex）
- `local_cert`：本地证书（base64 或 hex）

必须满足：`local_private_key_hex` 的公钥 == `local_cert` 内的公钥，否则握手会失败（见 `validateIdentity`）。

### 5.5 `bci`（测试/演示数据生成）

client 会在 `run*BCIEcho` 中使用 `internal/bci.Generator` 生成数据：

- `channels`：通道数（默认 8）
- `sample_rate_hz`：采样率（默认 256）
- `samples_per_channel`：每帧每通道采样点数（默认 32）
- `frames`：发送帧数
- `interval_ms`：每帧间隔（模拟实时链路）
- `seed`：确定性种子（便于复现）

BCI 帧的二进制格式见下节。

---

## 6. BCI 数据格式（如何生成/如何解析）

BCI 数据生成器：`internal/bci/sim.go`

每一帧 payload 为二进制（大端）：

1. `uint64 timestamp_unix_nano`
2. `uint16 channels`
3. `uint16 sample_rate_hz`
4. `uint16 samples_per_channel`
5. `int16[channels*samples_per_channel]`（channel-major interleaved）

你可以用任意语言解析这段 payload。

---

## 7. 如何编译与部署（跨平台）

详细：`doc/DEPLOYMENT.md`

常用命令：

```bash
go build -o iotbci ./cmd/iotbci
go build -o iotbci-keygen ./cmd/iotbci-keygen
go build -o iotbci-bench ./cmd/iotbci-bench
go build -o iotbci-evidence ./cmd/iotbci-evidence
go build -o iotbci-report ./cmd/iotbci-report
```

交叉编译（示例：OpenWrt/arm64）：

```bash
GOOS=linux GOARCH=arm64 go build -o iotbci ./cmd/iotbci
```

抓包工具（`cmd/iotbci-capture`）依赖 libpcap，通常需要 `CGO_ENABLED=1` 且目标平台安装了 libpcap 开发包；否则只能使用 stub 或改用外部抓包工具（tcpdump/Wireshark）。

---

## 8. 如何生成密钥/证书（多设备部署）

工具：`cmd/iotbci-keygen`

### 8.1 生成 master keypair

```bash
go run ./cmd/iotbci-keygen -gen-master
```

### 8.2 生成设备或服务端 keypair（随机）

```bash
go run ./cmd/iotbci-keygen -gen-key
```

### 8.3 从 master seed + device id 派生设备密钥（批量生产）

```bash
go run ./cmd/iotbci-keygen -derive-device-key -master-seed-hex <32bytes-hex> -device-id device-001
```

### 8.4 签发证书（master -> 设备/服务端）

```bash
go run ./cmd/iotbci-keygen -issue-cert -master-priv-hex <64bytes-hex> -subject device-001 -pub-hex <32bytes-hex> -serial 1 -days 365
```

把输出的 `cert_base64`（或 `cert_hex`）填入 config 的 `identity.local_cert`。

---

## 9. 如何跑测试（单测 / 竞态 / 压力）

### 9.1 单测（默认）

```bash
go test ./...
```

### 9.2 竞态检测（建议论文阶段也跑一次）

```bash
go test -race ./...
```

### 9.3 压力测试（build tag：`stress`）

```bash
go test -tags stress ./...
```

可调参数（环境变量）：

- `IOTBCI_STRESS_HANDSHAKES`：握手次数（默认 200）
- `IOTBCI_STRESS_CONCURRENCY`：并发握手上限（默认自动）
- `IOTBCI_STRESS_STREAMS`：mux streams 数（默认 256）
- `IOTBCI_STRESS_STREAM_PAYLOAD`：每个 stream payload 字节（默认 16384）

注意：压力测试不会默认在 `ci.yml` 里跑，而是放在 `stress.yml`（手动触发）避免拖慢 PR。

---

## 10. 如何读取“对比结果”和“测试结果”

### 10.1 `cmd/iotbci-bench` 输出（micro-bench）

输出 JSON 结构见 `internal/bench/report.go`：

- `core_source_bytes`：核心库源码体积（用于“核心库代码体积”指标）
- `payload_bytes_total`：应用层 payload 总字节（双向）
- `wire_bytes_total`：线上写出的 payload 字节总量（双向，不含 TCP/IP 头）
- `overhead_ratio = wire_bytes_total / payload_bytes_total`
- `avg_rtt_ms` / `p95_rtt_ms`：每次收发 RTT（更偏 CPU 编码/加密开销）
- `wire_entropy` / `wire_ascii_ratio`：线上 payload 字节的熵值/ASCII 比例
- `peak_*`：Go runtime 采样的峰值内存（论文需要注明采样方式和误差）

### 10.2 `cmd/iotbci-evidence` 输出（论文证据集）

目录结构：

- `evidence_out/evidence.json`：总览（包含所有 scenario 的 metrics + 可选抓包报告摘要）
- `evidence_out/<scenario>/metrics.json`：单场景指标
- `evidence_out/<scenario>/capture.pcap`：可选抓包
- `evidence_out/<scenario>/pcap_report/report.{json,md,html}`：可选报告

建议论文对比以 evidence 的真实 socket 流量为主，micro-bench 为辅（见 `doc/BENCHMARKS.md` 的说明）。

### 10.3 `cmd/iotbci-report` 输出（抓包报告）

报告统计项：

- payload 大小分布（log2 bins）
- inter-arrival 分布（log2 bins）
- payload 字节熵值、ASCII 比例
- 包/字节总量（便于和应用层 payload 合并计算 overhead）

详见 `doc/CAPTURE.md`。

---

## 11. 常见问题（Troubleshooting）

### 11.1 握手失败 / 连接被标记 suspicious

优先检查：

- client/server 的 `psk`、`handshake_aead`、`session_aead`、`enable_pure_downlink` 是否一致（否则会触发 option mismatch）
- `time_skew_sec` 是否过小（设备时间未同步时常见）
- 证书是否过期（`not_before/not_after`）
- `local_private_key_hex` 是否与 `local_cert` 匹配
- server 的 replay 窗口/容量是否太小导致误判（高频连接时）

### 11.2 抓包失败

- 没装 libpcap 或缺权限：`iotbci-capture` 会提示需要 `-tags pcap`
- macOS/Linux 上可能需要 `sudo` 或授予抓包权限
- loopback 接口名：macOS 常见 `lo0`；Linux 常见 `lo`

---

## 12. 扩展与二次开发（最小心智负担）

如果你要在论文后继续把它做成可部署协议，建议按如下方式扩展：

1) 优先使用 `apis/*` 对外 API（减少直接依赖内部结构）
2) 把“设备侧资源上限”（replay cache size、mux queued bytes、握手 size 上限）做成 config 可控项
3) 将 revocation list 以文件或远程下发方式接入 `ServerOptions.Revocation`
4) 对新 app 协议：尽量复用 session（握手 + record + obfs）层，只在最上层定义 payload framing

相关细节请继续阅读：

- `doc/SPEC.md`（封装与错误处理规范）
- `doc/SECURITY.md`（参数建议与威胁模型）
- `doc/OBFS_SUDOKU.md`（外观层可解析性/鲁棒性）

