# 05 基线对比实验留痕（DTLS / CoAP / MQTT / pure-AEAD vs IoTBCI-Sudoku）

## 目的

- 严格对齐进度计划表中的“补齐 TLS/DTLS 基线方案 / 三类方案对比实验准备”：
  - 说明**对比了什么**（指标定义、测量口径、实验条件）
  - 说明**如何对比**（运行方式、统一输入、验证点/正确性证据）
  - 给出**可截图/可复制**的结果与分析（含 Sudoku 优缺点）

## 产出（可截图/可复制）

- 可视化总报告：`out/report.html`
- 原始数据：
  - `out/bench.json`（`cmd/iotbci-bench` micro-bench）
  - `out/evidence_out/evidence.json`（`cmd/iotbci-evidence` 回环真实 socket）
  - `out/summary.json`、`out/summary.txt`（本 evidence pack 的结构化汇总与月报摘要）

## 复现

```bash
python3 run.py
open out/report.html
```

