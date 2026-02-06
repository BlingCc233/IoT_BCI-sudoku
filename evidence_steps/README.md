# evidence_steps（毕业设计留痕留档）

本目录用于对齐 `tex/4.毕业设计（论文）进度计划表.pdf` 的计划进度表，按“每个小任务一份证据包”的方式留痕留档：

- 每个任务一个子目录（`NN_*`），目录内包含：
  - `README.md`：目的/方法/结论（可直接复制到月报）
  - `run.py`：一键复现脚本（优先 python 验证，再落到 Go 实现/测试）
  - `out/report.html`：美观可视化结果（浏览器打开即可截图）
  - `out/*.json/*.txt/*.svg`：可复制的原始数据/图

快速运行（生成/刷新所有 `out/*`）：

```bash
bash evidence_steps/run_all.sh
```

总览（对齐进度计划表）：

- `evidence_steps/00_plan_alignment/out/report.html`
- 每一行计划的独立页面：`evidence_steps/00_plan_alignment/out/rows/*.html`

任务索引：

- 00 计划对齐：`evidence_steps/00_plan_alignment/README.md`
- 01 数独编解码验证（Python）：`evidence_steps/01_sudoku_codec_validation/out/report.html`
- 02 Padding + 自定义字节格式（x/v/p）：`evidence_steps/02_padding_custom_layout/out/report.html`
- 03 汉明距离（Hamming-1）分析工具：`evidence_steps/03_hamming1_analysis/out/report.html`
- 04 Go 单元测试留痕（握手/分帧/UoT/回落等）：`evidence_steps/04_go_unit_test_logs/out/report.html`
- 05 基线对比实验留痕（DTLS/CoAP/MQTT/pure-AEAD vs IoTBCI-Sudoku）：`evidence_steps/05_baseline_comparison/out/report.html`
- 06 协议指纹 + 侧写 + DPI/MITM 对照：`evidence_steps/06_fingerprint_sidechannel/out/report.html`

新增任务（建议流程）：

1. 复制模板：`cp -R evidence_steps/_template_step evidence_steps/NN_your_task_name`
2. 在任务 `README.md` 写清：目标、输入、输出、结论、下一步
3. 先用 `run.py` 做验证与可视化，再把结论落实到 Go 实现/测试中，并把关键输出留在 `out/`

补充：仓库级进度清单可参考 `doc/PROGRESS_CHECKLIST.md`。
