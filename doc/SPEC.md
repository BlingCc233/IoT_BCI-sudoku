# Protocol Specification (IoT BCI Sudoku)

> Status: implementation-first (v0). Code is the source of truth under `pkg/iotbci`, `pkg/obfs/sudoku`, `pkg/iotbci/mux`, `pkg/iotbci/uot`.

## 0. 术语

- **RawConn**：底层 TCP 连接（`net.Conn`）。
- **ObfsConn**：数独外观层后的字节流连接（仍是 `net.Conn`，但对外暴露的 Read/Write 是“解码后的字节流”）。
- **HandshakeConn**：握手阶段的通道（可选 PSK-AEAD 保护）。
- **SessionConn**：握手完成后的会话通道（前向安全密钥的 AEAD record）。

## 1. 目标

- 局域网 BCI 通信：重点防侧写（traffic appearance hardening）、防重放、抗 MITM。
- 小内存设备可部署：所有核心状态 **可设上限**（重放窗口缓存、mux 队列、单帧大小等）。
- 工程可落地：错误分类、可疑流量回落、可测试、可量化评估（bench + 抓包报告）。

## 2. 非目标

- `httpmask` / HTTP 伪装 / CDN tunnel：全部删除，不作为 IoT BCI 方向的一部分。

## 3. 分层结构（从下到上）

```
TCP RawConn
  -> Sudoku Obfs (uplink: sudoku; downlink: sudoku or packed)
    -> HandshakeConn (optional PSK AEAD record)
      -> Handshake frames (IBC1)
        -> SessionConn (forward-secure AEAD record, per-direction keys)
          -> Application (stream / mux / UoT)
```

## 4. AEAD record 封装格式（SessionConn/HandshakeConn）

实现：`pkg/iotbci/recordconn.go`

### 4.1 record 格式

- `uint16 ciphertext_len`（大端）
- `ciphertext[ciphertext_len]`

### 4.2 nonce 规则（不随包发送）

- `nonce = salt4 || seq64`（共 12 bytes）
- `seq64` 为单方向计数器，从 0 递增（TCP 保序，无丢包重排，保证两端一致）

### 4.3 支持算法

- `chacha20-poly1305`
- `aes-128-gcm`
- `none`（仅用于对比/调试；BCI 场景不建议）

## 5. Handshake frame 格式

实现：`pkg/iotbci/handshake_frame.go`

- `magic[4] = "IBC1"`
- `version[1] = 0x01`
- `msg_type[1]`
- `uint16 body_len`
- `body[body_len]`

`msg_type`：
- `0x01` ClientHello
- `0x02` ServerHello
- `0x03` ClientFinish

## 6. Handshake 消息体（字段顺序与长度）

实现：`pkg/iotbci/handshake_messages.go`

### 6.1 ClientHello body

```
uint16 flags
uint64 timestamp_unix_sec
byte[16] nonce_c
byte[8]  user_hash = Trunc8(SHA256(ed25519_seed))
byte[32] x25519_ephemeral_pub_c
uint16 cert_len
byte[cert_len] cert
byte[64] ed25519_sig_over(body_without_sig)
```

### 6.2 ServerHello body

```
uint16 flags
uint64 timestamp_unix_sec
byte[16] nonce_s
byte[16] echo_nonce_c
byte[32] x25519_ephemeral_pub_s
uint16 cert_len
byte[cert_len] cert
byte[32] client_hello_hash = SHA256(client_hello_body_without_sig)
byte[64] ed25519_sig_over(body_without_sig)
```

### 6.3 ClientFinish body

```
byte[32] client_hello_hash
byte[32] server_hello_hash = SHA256(server_hello_body_without_sig)
byte[16] mac = Trunc16(HMAC-SHA256(confirm_key, client_hello_hash || server_hello_hash))
```

## 7. flags 编码（`uint16`）

实现：`pkg/iotbci/handshake_messages.go`

- bits[0..1]：Session AEAD
  - `0` none
  - `1` aes-128-gcm
  - `2` chacha20-poly1305
- bit[2]：Downlink mode
  - `1` pure
  - `0` packed

## 8. 重放窗口与异常处置

实现：`pkg/iotbci/replay.go` + `pkg/iotbci/handshake_server.go`

- 时间戳校验：`abs(now - ts) <= TimeSkew`
- 重放缓存 token（示例）：`user_hash || nonce_c || cert_serial`
- 缓存为固定容量环形队列，确保小内存设备可控。

## 9. 可疑流量回落（fallback）

当握手解码失败/认证失败/重放时，服务端返回 `*iotbci.SuspiciousError`，其中：

- `Err`：分类错误（可 `errors.Is` 匹配）
- `Conn`：实现 `GetBufferedAndRecorded()` 的连接包装，用于取出已经读取的**原始字节流**并转发到诱饵服务。

参考实现可见原 Sudoku 工程的 fallback 处理风格；本仓库将其作为协议核心的工程契约保留。

