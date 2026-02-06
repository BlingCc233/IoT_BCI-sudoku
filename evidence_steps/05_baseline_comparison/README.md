# 05 基线对比实验留痕（DTLS / CoAP / MQTT / pure-AEAD vs IoTBCI-Sudoku）

## 目的

- 严格对齐进度计划表中的“补齐 TLS/DTLS 基线方案 / 三类方案对比实验准备”：
  - 说明**对比了什么**（指标定义、测量口径、实验条件）
  - 说明**如何对比**（运行方式、统一输入、验证点/正确性证据）
  - 给出**可截图/可复制**的结果与分析（含 Sudoku 优缺点）

## 产出（可截图/可复制）

- 可视化总报告：`out/report.html`
- 原始数据：
  - `out/bench.json`（`cmd/iotbci-bench` micro-bench，run1）
  - `out/evidence_out/evidence.json`（`cmd/iotbci-evidence` 回环真实 socket，run1）
  - `out/bench_r2.json`、`out/bench_r3.json`（重复运行）
  - `out/evidence_out_r2/evidence.json`、`out/evidence_out_r3/evidence.json`（重复运行）
  - `out/summary.json`、`out/summary.txt`（本 evidence pack 的结构化汇总与月报摘要）

## 关键口径

- 默认做 3 次重复运行并取中位数，减少单次调度抖动。
- `Guard` 规则：除 overhead 外，`iotbci-sudoku-pure` 与 `iotbci-sudoku-packed` 的
  `avg_rtt_ms` + `peak_heap_inuse_bytes` 必须同时低于 DTLS 与 MQTT，且在 bench/evidence 两套 benchmark 都成立。

## 复现

```bash
python3 run.py
open out/report.html
```
