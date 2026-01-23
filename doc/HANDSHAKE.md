# Handshake & Anti-Replay

实现代码：
- Client：`pkg/iotbci/handshake_client.go`
- Server：`pkg/iotbci/handshake_server.go`

## 1. 握手目标

- 双向身份认证：Ed25519 证书 + 签名验证（抗 MITM）。
- 前向安全：会话密钥来自 X25519 临时密钥交换（即使 PSK 泄露也不应解密历史会话）。
- 抗重放：时间戳窗口 + 有界 nonce 缓存（工程可测、可证明有效）。
- 抗主动探测：握手通道可选 PSK-AEAD 保护，使未授权探测难以获得可区分响应。

## 2. 时序（3 步）

```
Client                                  Server
  |-- ClientHello (sig) ------------------>|
  |<------------------ ServerHello (sig) --|
  |-- ClientFinish (HMAC confirm) -------->|
  |========= switch to SessionConn ========|
```

## 3. 认证与绑定点

### 3.1 ClientHello

服务端在通过以下校验后，才会写入重放缓存：

1) frame magic/version/type 合法；
2) 时间戳窗口合法；
3) 证书验证（MasterPublicKey 或 pin）；
4) ClientHello 的 Ed25519 签名验证通过；
5) `flags` 与本端配置一致（避免 downgrade/配置不一致）。

### 3.2 ServerHello

客户端验证：

1) `echo_nonce_c` 必须等于本端 `nonce_c`（防反射/绑定会话）；
2) 证书验证；
3) ServerHello 的 Ed25519 签名验证；
4) `client_hello_hash` 必须匹配（绑定 ClientHello）。

### 3.3 ClientFinish

服务端验证 `HMAC(confirm_key, client_hello_hash || server_hello_hash)`：

- 若通过：证明客户端具备 ECDH 共享密钥并完成握手。
- 若失败：按可疑流量处理（不返回真实数据，可回落）。

## 4. 抗重放窗口

### 4.1 时间戳窗口

- `abs(now - ts) <= TimeSkew`（默认 30s，建议 LAN 场景 10~60s）

### 4.2 nonce 缓存（有界）

- Token：`user_hash || nonce_c || cert_serial`
- 缓存：固定容量环形队列（`ReplayCacheSize`），过期窗口（`ReplayWindow`）
- 行为：命中 -> 返回 `ErrReplayDetected`（服务端应记录并触发回落策略）

## 5. 工程落地注意事项

- **小内存**：`ReplayCacheSize`、`MaxHandshakeSize`、`HandshakeTimeout` 必须可配置。
- **日志策略**：对重放/认证失败应记录，但不得输出敏感材料（PSK/私钥种子/明文）。
- **异常处置**：服务端对可疑握手返回 `*SuspiciousError`，供上层统一回落到诱饵服务或 tarpit。

