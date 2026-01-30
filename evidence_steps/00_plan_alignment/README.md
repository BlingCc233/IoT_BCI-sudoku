# 00 计划对齐（tex/进度计划表）

对齐对象：

- 计划表 PDF：`tex/4.毕业设计（论文）进度计划表.pdf`
- 仓库级检查清单：`doc/PROGRESS_CHECKLIST.md`

本目录用于把“计划表上的每一项”落成“可复现 + 可截图 + 可复制”的证据包（见 `evidence_steps/README.md` 的结构约定）。

生成对齐报告（含每一行计划的独立 HTML 页面，便于逐条截图）：

```bash
python3 run.py
open out/report.html
open out/rows/S7_W10-11.html
```

建议你把计划表里的每一行任务，映射成一个 `NN_*` 子目录，并在该目录内留：

- 结论（可直接贴进月报）
- 关键输出（`out/report.html` + `out/*.txt/*.json/*.svg`）
- 可复现脚本（优先 python 验证，再实现到 Go）

你可以从模板开始：`cp -R evidence_steps/_template_step evidence_steps/NN_your_task_name`
