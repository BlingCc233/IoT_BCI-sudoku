# GitHub vs Gitea 推送策略（“模板公开 + 论文私有”）

Git 的 `.gitignore` **无法按 remote 区分**（同一个分支上被 commit 的文件，push 到哪个 remote 都会带过去）。如果你希望：

- **Gitea**：可以 push 全部（代码 + `tex/` 模板 + 论文正文 + 论文图表等）
- **GitHub**：只 push 模板（以及公开的代码），**不包含论文正文/图表等敏感内容**

推荐做法是维护 **两条分支**：

- `main`：用于 Gitea（全量，包括论文）
- `github`：用于 GitHub（删掉或替换敏感目录，只保留模板与公开代码）

## 1) 目录约定（建议）

将敏感论文内容集中放在固定目录，便于在 `github` 分支一键剔除，例如：

- `tex/thesis/`：论文正文（敏感）
- `tex/generated/`：论文用的生成图表/表格（若含敏感数据也可归类为敏感）
- 其它你认为敏感的：例如开题报告、进度表、原始实验数据等

模板与可公开内容（可留在 GitHub）：

- `tex/thesis-uestc.cls` / `tex/thesis-uestc.bst` / `tex/README.md` 等模板文件
- `tex/main.tex` / `tex/main_multifile.tex`（如果只是“示例/模板”，不写真实内容）

## 2) 分支推送方式

假设你有两个 remote：

- `gitea`：私有或内部
- `origin`：GitHub

推送：

```bash
git push gitea main
git push origin github
```

## 3) 快速同步 `github` 分支（脚本思路）

你可以用一个脚本把 `github` 分支从 `main` 同步出来，并删除敏感目录后再推送。

仓库内可放一个脚本（示例逻辑）：

1. 确保工作区干净（`git status`）
2. `git checkout github`（不存在则创建）
3. `git reset --hard main`
4. `rm -rf tex/thesis tex/generated ...`
5. `git commit -am "sync github branch (remove private thesis)"`
6. `git push origin github`

注意：脚本会执行 `git commit`，建议在你确认后手动运行。

