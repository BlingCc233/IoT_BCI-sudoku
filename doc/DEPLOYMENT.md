# Deployment Guide

This document covers:

- Key/cert generation for multi-device deployments
- Revocation workflow
- Recommended defaults for small-memory devices
- CI and reproducibility notes

## 1. 身份与密钥管理（多设备）

本仓库提供“主公钥统一管理 + 设备证书”模型：

- Master（制造/运维侧）持有 Ed25519 master private，用于签发设备/服务端证书；
- 部署侧只需要 master public（可公开），用于验证证书；
- 设备私钥可用 master seed + deviceID 通过 HKDF 确定性派生（便于批量生产与吊销）。

相关实现：

- 证书：`pkg/iotbci/cert.go`
- 私钥派生：`iotbci.DeriveEd25519Seed`

### 1.1 设备 seed 派生

```go
seed, _ := iotbci.DeriveEd25519Seed(masterSeed, "device-001")
priv := ed25519.NewKeyFromSeed(seed[:])
pub := priv.Public().(ed25519.PublicKey)
```

### 1.2 签发证书

```go
cert, _ := iotbci.IssueCert(masterPriv, "device-001", pub, notBefore, notAfter, serial)
```

## 2. 吊销（Revocation）

服务端可维护 `RevocationList`：

- 按 `Serial` 吊销
- 按 `Subject`（deviceID）吊销

握手验证入口：`iotbci.ServerHandshake` 会在 `verifyPeerCert` 中检查吊销名单。

## 3. 小内存设备推荐默认

- `MaxHandshakeSize`：建议 4~16KB
- `ReplayCacheSize`：根据可接受连接速率选择（例如 1024/4096）
- `ReplayWindow`：LAN 场景建议 30s~2min
- `mux.Config.MaxQueuedBytes*`：按 RAM 上限反推（避免拥塞时队列无限增长）

## 4. CI / 可复现

- `ci.yml`：`gofmt` / `go vet` / `go test`
- `bench.yml`：手动触发基准输出 JSON（可作为论文实验脚本的一部分）

## 5. 可执行文件构建（跨平台）

本仓库提供可直接部署的可执行文件入口：

- 协议节点（server/client）：`cmd/iotbci`
- 证书/密钥工具：`cmd/iotbci-keygen`
- 对比/证据集工具：`cmd/iotbci-bench`、`cmd/iotbci-evidence`、`cmd/iotbci-capture`、`cmd/iotbci-report`
- 攻击模拟：`cmd/iotbci-attack`
- 统一可视化：`cmd/iotbci-dashboard`
- LaTeX 图表/表格生成：`cmd/iotbci-texgen`

示例（本机构建）：

```bash
go build -o iotbci ./cmd/iotbci
go build -o iotbci-keygen ./cmd/iotbci-keygen
```

示例（交叉编译到 OpenWrt/arm64）：

```bash
GOOS=linux GOARCH=arm64 go build -o iotbci ./cmd/iotbci
```

示例配置见 `configs/dev_*.json`（stream/mux/uot）。
