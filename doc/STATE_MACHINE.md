# State Machine

## 1. TCP 会话

```
RAW_CONNECTED
  -> (Sudoku obfs ready)
    -> HANDSHAKE_CLIENT_HELLO_SENT / HANDSHAKE_SERVER_WAIT_HELLO
      -> HANDSHAKE_SERVER_HELLO_SENT / HANDSHAKE_CLIENT_WAIT_HELLO
        -> HANDSHAKE_CLIENT_FINISH_SENT / HANDSHAKE_SERVER_WAIT_FINISH
          -> SESSION_ESTABLISHED (SessionConn)
            -> (optional) MUX_MODE
            -> (optional) UOT_MODE
              -> SESSION_CLOSED
```

## 2. Handshake 错误路径（服务端）

- 任何阶段出现：
  - frame 格式错误
  - 解密失败
  - 证书验证失败
  - 签名校验失败
  - `flags` 不一致（疑似 downgrade/配置不一致）
  - 时间戳超窗
  - 重放命中

都应进入：

```
SUSPICIOUS
  -> return *SuspiciousError (contains Conn evidence)
    -> upper layer: fallback/decoy/tarpit
```

## 3. Mux（多路复用）

实现：`pkg/iotbci/mux`

### 3.1 Preface

- `0xED 0x01`

### 3.2 Frame 生命周期

- OPEN -> DATA* -> CLOSE
- OPEN -> RESET -> CLOSE

### 3.3 内存与 DoS 限制

- `MaxStreams`
- `MaxQueuedBytesPerStream`
- `MaxQueuedBytesTotal`
- 超限行为：关闭/重置对应 stream，保持 session 可恢复。

## 4. UoT（UDP-over-TCP）

实现：`pkg/iotbci/uot`

- Preface：`0xEE 0x01`
- Datagram frame：`addrLen|payloadLen|addr|payload`

`PacketConn` 语义：
- `WriteTo`/`ReadFrom` 在 TCP 上实现“可靠的 datagram framing”
- 若接收缓冲不足，返回 `io.ErrShortBuffer`，并丢弃多余字节以保持 framing 对齐。

