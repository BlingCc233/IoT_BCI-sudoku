# Sudoku Appearance Layer

This layer provides:

- 1 byte plaintext -> 4 hint bytes (order permuted)
- Arbitrary padding bytes inserted between hints
- Optional packed mode: 6-bit groups -> 1 hint byte (+ pad marker), for throughput-first profiles
- ASCII preference or entropy preference
- Custom x/v/p bit-layout table (semantic corrected):
  - `x`: redundant bits (2 bits)
  - `p`: position bits (4 bits)
  - `v`: value bits (2 bits)

Implementation: `pkg/obfs/sudoku`.

## Packed 模式（6-bit groups）

除了 “1 byte -> 4 hints” 的纯数独编解码外，本仓库还提供 `PackedConn`（`pkg/obfs/sudoku/packed.go`）：

- 写入路径：按 6-bit 分组，将每组编码为 1 个 hint byte（更接近 base64 风格，但仍受 layout.isHint/自定义 x/v/p 外观控制）
- 读出路径：跳过 padding，按组还原回字节流
- 适合与 AEAD ciphertext 叠加，用于吞吐/时延优先的 profile

在 `pkg/iotbci` 中可通过 `ObfsOptions.EnablePackedUplink` 打开 uplink（client->server）打包；与 `EnablePureDownlink=false` 组合时即为双向 packed。

## 自定义 x/v/p 外观（语义纠错说明）

原版 Sudoku 的自定义字段描述存在语义混淆。本仓库在实现层面按以下语义固定：

- `x`：冗余位（2 bits），用于构造 hint byte 的“恒定标记位”（layout.isHint 依赖）。
- `p`：位置位（4 bits），编码 4x4 网格中的 cell position（0..15）。
- `v`：值位（2 bits），编码 cell value（0..3 对应原 Sudoku 值 1..4）。

### Pattern 规则

- pattern 长度固定 8（对应一个字节的 bit7..bit0）
- 必须且仅能包含：
  - 2 个 `x`
  - 4 个 `p`
  - 2 个 `v`

示例：`xppppxvv`、`vppxppvx`

实现：`pkg/obfs/sudoku/layout.go:newCustomLayout`

## 鲁棒性约束

- 解码器只识别 layout.isHint 的字节作为 hint；其余全部视为 padding/噪声并跳过。
- 每 4 个 hint 组成一个无序集合，通过排序网络生成 key 并查表解码（避免因乱序导致歧义）。
- 对 map miss 直接返回错误（上层应触发可疑流量路径，避免状态机资源耗尽）。
