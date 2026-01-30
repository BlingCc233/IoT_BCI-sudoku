# 03 汉明距离（Hamming-1）分析工具

## 目的

- 对 hint 字节集 vs padding 字节集做汉明距离统计（尤其关注距离=1 的对）
- 用于说明“自定义 x/v/p 布局 + padding 池构造”的鲁棒性边界：
  - 单比特翻转可能导致 padding 被误判为 hint（或 hint 被误判为 padding）

## 产出（可截图/可复制）

- 可视化：`out/report.html`（距离直方图 + 示例对）
- 原始数据：`out/summary.json`、`out/distance1_pairs.txt`

## 复现

```bash
python3 run.py
open out/report.html
```

