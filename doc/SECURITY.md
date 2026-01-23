# Threat Model & Mitigations

## Threats

- Replay: attacker records packets and replays them to trigger repeated control commands.
- MITM: attacker impersonates one side, attempts to tamper or analyze traffic appearance.

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
