# 02 Padding + 自定义字节格式（x/v/p）验证

## 目的

- 验证 `x/v/p` 自定义 pattern（例如 `xppppxvv` / `vppxppvx`）的：
  - hint 字节可被可靠识别（`isHint`）
  - padding 池永远不会被识别为 hint（通过“丢 1 个 x 位”构造）
  - padding 的汉明重量（popcount）满足“看起来更忙”的约束（`>=5`）

## 产出（可截图/可复制）

- 可视化：`out/report.html`（包含 0..255 字节空间热力图 + 直方图）
- 原始数据：`out/summary.json`、`out/summary.txt`

## 复现

```bash
python3 run.py
open out/report.html
```

