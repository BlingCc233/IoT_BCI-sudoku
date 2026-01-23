# Suspicious Traffic Fallback

When the server detects malformed handshake, replay, or protocol violations, it can:

- Record minimal evidence (bounded)
- Switch the connection to a decoy handler (no real data)
- Keep logs safe (rate-limited, do not leak secrets)

## 协议层契约

`iotbci.ServerHandshake` 在可疑场景会返回 `*iotbci.SuspiciousError`：

- `Err`：原因（例如 `ErrReplayDetected`、`ErrAuthFailed`、`ErrProtocolViolation`）
- `Conn`：一个实现 `GetBufferedAndRecorded()` 的连接包装

`GetBufferedAndRecorded()` 返回的是**原始线上字节**（未解码），上层可以：

1) 先把这段已读数据写入诱饵服务（例如 nginx）；
2) 再把 `rawConn` 剩余数据双向转发。

这样主动探测者看到的是“正常服务响应”，不会得到真实协议数据路径上的任何信息。
