# 04 Go 单元测试留痕（握手/分帧/UoT/回落等）

## 目的

- 把计划表中的“单元测试日志/正确性验证”做成可复现、可截图、可复制的证据：
  - 握手（Ed25519 + 密钥派生 + 抗重放）
  - TCP 流分帧
  - UoT（UDP over TCP）
  - 可疑流量回落/异常处理

## 产出（可截图/可复制）

- `out/report.html`：每个模块的“Claims + Algorithm + 测试用例(-v) + 原始输出 + 源码证据”
- `out/results.json`：结构化结果（便于月报/周报引用）
- `out/summary.txt`：一段可直接复制到月报的摘要

## 复现

```bash
python3 run.py
open out/report.html
```
