# 01 数独编解码验证（Python + Go 对齐导出）

## 目的

- 用 Python 生成“可视化 + 过程追踪”，并用 Go 导出数据保证与实现对齐，验证：
  - `plaintext -> (padding + 4*hints)` 编码流程可行
  - 只根据 `isHint` 过滤 padding 后，4 个 hint 可无序解码回原字节
  - 对每个字节：展示 `byte -> 4x4 Sudoku` 的全量映射（256 项）
  - 展示“题目(puzzle)选择/乱序/填充/解码”的全过程，并给出两次编码同一 payload 输出不同的证据

## 产出（可截图/可复制）

- 可视化：`out/report.html`（含 byte->grid 全量映射、puzzle 示例、编码/解码追踪、两次编码对比）
- 原始数据：`out/summary.json`
- Go 导出：`out/go_dump_*.json`（全量 EncodeTable + byte->grid；由 `cmd/iotbci-evidence-sudoku-dump` 生成）

## 复现

```bash
python3 run.py
open out/report.html
```
