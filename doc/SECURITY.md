# Threat Model & Mitigations

## Threats

- Replay: attacker records packets and replays them to trigger repeated control commands.
- MITM: attacker impersonates one side, attempts to tamper or analyze traffic appearance.
- Resource exhaustion: attacker floods invalid probes/frames to consume CPU/memory/state.

## Expected behavior

- Replay attempts are logged and trigger fallback/decoy behavior; real data is never returned.
- MITM sees non-fixed byte appearance and cannot reliably fingerprint traffic; authentication prevents endpoint impersonation.

## 观察点与应对（论文可写点）

### 1) 重放攻击

观察点：
- 记录历史握手/会话包，在时间窗内重放；
- 期望诱发重复控制指令或扰乱会话状态。

应对：
- **时间戳窗口**：超窗直接拒绝；
- **nonce 重放缓存**：窗内重复直接拒绝；
- **异常处置**：返回 `SuspiciousError`，上层可回落到诱饵服务，避免给出真实数据路径响应。

### 2) MITM

观察点：
- 攻击者插入链路中伪装通信双方；
- 目标篡改数据、注入控制命令、或通过流量外观侧写协议特征。

应对：
- **身份认证**：证书验证 + Ed25519 签名绑定 X25519 临时公钥；
- **会话密钥前向安全**：会话 key 来自 ECDH（握手通道 PSK 仅用于抗探测与额外保护）；
- **外观层**：Sudoku/ASCII/随机 padding/下行 packed，使长度、字节分布、可打印比例不固定。

### 3) 资源耗尽（内存/状态机崩溃）

观察点：
- 构造异常输入让解码器无限缓冲/无限队列增长；
- 或让 mux 子流队列无限堆积。

应对：
- `MaxHandshakeSize` 限制握手消息体；
- `ReplayCacheSize`/`ReplayWindow` 限制重放缓存；
- mux 侧 `MaxQueuedBytesPerStream`/`MaxQueuedBytesTotal` 限制队列增长；
- 任何协议违规进入可疑路径，不进入真实数据处理逻辑。

## 可复现实验（工具模拟）

本仓库提供了一个最小化的攻击模拟工具，用于在本机进程内复现“应当被拒绝/被标记可疑”的行为：

```bash
go run ./cmd/iotbci-attack -timeout 10s -out attack_report.json
```

输出包含：

- `replay`：复用上一轮抓到的 client->server 握手字节，期望触发 `ErrReplayDetected`
- `mitm-tamper`：对链路中首个写入进行 bit-flip，期望握手在可疑路径失败（`SuspiciousError` / `AuthFailed` / `ProtocolViolation`）
- `resource-probe-flood`：发送大量无效探测数据，期望 server 快速拒绝且不进入真实数据逻辑
