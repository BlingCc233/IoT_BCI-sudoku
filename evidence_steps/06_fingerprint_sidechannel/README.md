# 06 协议指纹 + 侧写 + DPI/MITM 对照留痕

## 目的

- 给出“仅看包长/序列特征就能识别协议类型”的可复现实验（aparecium 风格的长度序列分析）。
- 用自拟 BCI 类别（多次重发）验证攻击者能否从侧写记录恢复原始类别。
- 对比 Sudoku `padding=0` 与 `padding>0`：展示 padding 对侧写恢复准确率的抑制效果。
- 展示 ASCII 模式在 DPI 场景下“看起来像明文”的伪装效果，同时强调语义不可直接理解。
- 给出 TLS MITM 可完全恢复明文类别、以及 Sudoku MITM 篡改被拒绝的对照证据。

## 产出

- 可视化总报告：`out/report.html`
- 结构化结果：`out/summary.json`、`out/summary.txt`
- 协议指纹特征导出：`out/aparecium_style_protocol_features.csv`
- 关联原始数据：
  - `out/proto_runs/*/evidence.json`
  - `out/bci_runs/*/evidence.json`
  - `out/attack_report.json`
  - `out/tls_mitm_demo.json`

## 复现

```bash
python3 run.py
open out/report.html
```

