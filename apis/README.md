# apis (public Go API)

This folder provides a stable, high-level API for embedding the **IoT_BCI-sudoku** protocol in other Go programs.

## Install

```bash
go get github.com/BlingCc233/IoT_BCI-sudoku
```

## Minimal client

```go
cfg := apis.DefaultClientConfig()
cfg.Security.PSK = "shared-psk"
cfg.Identity.MasterPublicKey = masterPub
cfg.Identity.LocalPrivateKey = clientPriv
cfg.Identity.LocalCert = clientCert

conn, meta, err := apis.Dial(ctx, "server:9000", cfg)
_ = meta
_ = conn
```

## Minimal server (single connection)

```go
cfg := apis.DefaultServerConfig()
cfg.Security.PSK = "shared-psk"
cfg.Identity.MasterPublicKey = masterPub
cfg.Identity.LocalPrivateKey = serverPriv
cfg.Identity.LocalCert = serverCert

raw, _ := ln.Accept()
sess, meta, err := apis.ServerHandshake(ctx, raw, cfg)
_ = meta
_ = sess
```

## Mux and UoT

- Mux: `apis.DialMux`, `apis.AcceptMux` (see `pkg/iotbci/mux`)
- UoT: `apis.DialUoT`, `apis.AcceptUoT` (see `pkg/iotbci/uot`)

## Fallback on suspicious traffic

`iotbci.ServerHandshake` can return `*iotbci.SuspiciousError`. The error contains a partially-consumed connection so you can implement decoy/fallback without losing bytes.

