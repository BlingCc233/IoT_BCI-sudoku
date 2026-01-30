#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

from pypdf import PdfReader

import sys

EVIDENCE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EVIDENCE_ROOT.parent
sys.path.append(str(EVIDENCE_ROOT / "_lib"))

from report import esc, html_page, now_local_str, write_json, write_text  # noqa: E402


_ROW_RE = re.compile(r"(?P<semester>七学期|八学期)\s*(?P<w1>\d+)\s*—\s*(?P<w2>\d+)\s*周")


def extract_pdf_text(pdf_path: Path) -> str:
    reader = PdfReader(str(pdf_path))
    parts: list[str] = []
    for i, page in enumerate(reader.pages):
        text = page.extract_text() or ""
        parts.append(text.strip())
        parts.append("\n")
    return "\n".join(parts).strip() + "\n"


def parse_rows(text: str) -> list[dict[str, object]]:
    matches = list(_ROW_RE.finditer(text))
    rows: list[dict[str, object]] = []
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        chunk = text[start:end].strip()

        semester_cn = m.group("semester")
        semester = "S7" if semester_cn == "七学期" else "S8"
        w1 = int(m.group("w1"))
        w2 = int(m.group("w2"))
        week_range = f"{w1}-{w2}"
        row_id = f"{semester}_W{week_range}"

        rest = chunk[m.end() - start :].strip()
        # The PDF text often separates "plan" and "deliverables" with >=2 spaces.
        parts = re.split(r"\s{2,}", rest, maxsplit=1)
        plan = parts[0].strip()
        deliverables_text = parts[1].strip() if len(parts) > 1 else ""
        deliverables = [x.strip() for x in re.split(r"[；;]\s*", deliverables_text) if x.strip()]

        rows.append(
            {
                "id": row_id,
                "semester_cn": semester_cn,
                "semester": semester,
                "weeks": {"from": w1, "to": w2, "range": week_range},
                "plan": plan,
                "deliverables": deliverables,
                "raw": chunk,
            }
        )
    return rows


def default_evidence_mapping(row: dict[str, object]) -> list[str]:
    raw = (row.get("plan") or "") + " " + " ".join(row.get("deliverables") or [])
    raw = str(raw)

    evidence: list[str] = []

    # Existing evidence packs
    if "数独" in raw or "编码" in raw:
        evidence.append("evidence_steps/01_sudoku_codec_validation/out/report.html")
    if "外观层" in raw or "obfs" in raw or "填充" in raw or "轮转" in raw:
        evidence.append("evidence_steps/02_padding_custom_layout/out/report.html")
        evidence.append("evidence_steps/03_hamming1_analysis/out/report.html")
    if (
        "握手" in raw
        or "分帧" in raw
        or "TCP流分帧" in raw
        or "UoT" in raw
        or "回落" in raw
        or "异常处置" in raw
        or "异常处理" in raw
        or "单元测试" in raw
    ):
        evidence.append("evidence_steps/04_go_unit_test_logs/out/report.html")
    if (
        "基线" in raw
        or "TLS" in raw
        or "DTLS" in raw
        or "CoAP" in raw
        or "MQTT" in raw
        or "对比" in raw
        or "实验" in raw
    ):
        evidence.append("evidence_steps/05_baseline_comparison/out/report.html")

    # Repo docs (as evidence for design/planning rows)
    if "威胁模型" in raw:
        evidence.append("doc/SECURITY.md")
    if "状态机" in raw:
        evidence.append("doc/STATE_MACHINE.md")
    if "报文" in raw or "字段" in raw or "规范" in raw:
        evidence.append("doc/SPEC.md")
    if "握手" in raw or "Ed25519" in raw:
        evidence.append("doc/HANDSHAKE.md")
    if "异常" in raw or "回落" in raw:
        evidence.append("doc/FALLBACK.md")
    if "抓包" in raw or "流量分析" in raw:
        evidence.append("doc/CAPTURE.md")
    if "实验" in raw or "对比" in raw:
        evidence.append("doc/BENCHMARKS.md")

    # De-dup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for p in evidence:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    rows_dir = out_dir / "rows"
    rows_dir.mkdir(parents=True, exist_ok=True)

    pdf_path = REPO_ROOT / "tex" / "4.毕业设计（论文）进度计划表.pdf"
    if not pdf_path.exists():
        raise FileNotFoundError(f"missing schedule PDF: {pdf_path}")

    text = extract_pdf_text(pdf_path)
    rows = parse_rows(text)

    for row in rows:
        row["evidence_links"] = default_evidence_mapping(row)

    payload = {
        "generated_at": now_local_str(),
        "pdf": str(pdf_path.relative_to(REPO_ROOT)),
        "rows": rows,
    }
    write_text(out_dir / "plan_extracted.txt", text)
    write_json(out_dir / "plan_rows.json", payload)

    # Per-row pages (one HTML per plan row, for screenshot/copy).
    for row in rows:
        rid = str(row["id"])
        links = row.get("evidence_links") or []
        links_html = (
            "<ul>" + "".join(f"<li><code>{esc(p)}</code></li>" for p in links) + "</ul>"
            if links
            else "<span class=\"badge warn\">TODO: add evidence links</span>"
        )
        deliverables = row.get("deliverables") or []
        deliverables_html = (
            "<ul>"
            + "".join(f"<li><input type=\"checkbox\" disabled /> {esc(x)}</li>" for x in deliverables)
            + "</ul>"
            if deliverables
            else "<span class=\"small\">(none parsed)</span>"
        )

        row_body = (
            f"<h1>{esc(rid)}（计划进度表单行留痕）</h1>"
            "<div class=\"card\">"
            "<table>"
            f"<tr><th>周次</th><td><code>{esc(rid)}</code></td></tr>"
            f"<tr><th>计划表 PDF</th><td><code>{esc(str(pdf_path.relative_to(REPO_ROOT)))}</code></td></tr>"
            "</table>"
            "</div>"
            "<div class=\"card\">"
            "<h2>主要工作计划</h2>"
            f"<pre>{esc(row.get('plan',''))}</pre>"
            "</div>"
            "<div class=\"card\">"
            "<h2>预期产出（计划表）</h2>"
            f"{deliverables_html}"
            "</div>"
            "<div class=\"card\">"
            "<h2>当前证据（仓库内路径）</h2>"
            f"{links_html}"
            "<div class=\"small\">"
            "说明：此处路径用于点击打开/复制到月报；若某项产出尚未完成，请在后续补齐对应 evidence pack（含 out/report.html + 原始数据）。"
            "</div>"
            "</div>"
        )
        write_text(rows_dir / f"{rid}.html", html_page(f"{rid} 计划对齐留痕", row_body))

    # Render a copy-friendly report.
    missing_rows = [r for r in rows if not r.get("evidence_links")]
    body_parts: list[str] = []
    body_parts.append("<h1>00 计划对齐（进度计划表 -> evidence_steps 留痕）</h1>")
    body_parts.append(
        "<div class=\"card\">"
        "<div class=\"small\">此报告从 <code>tex/4.毕业设计（论文）进度计划表.pdf</code> 抽取每一行计划，并给出在仓库内的证据链接（HTML/JSON/文档/测试）。</div>"
        "<table>"
        f"<tr><th>PDF</th><td><code>{esc(str(pdf_path.relative_to(REPO_ROOT)))}</code></td></tr>"
        f"<tr><th>rows</th><td>{len(rows)}</td></tr>"
        f"<tr><th>rows without evidence links</th><td>{len(missing_rows)}</td></tr>"
        "</table>"
        "<div class=\"small\">导出文件：<code>out/plan_extracted.txt</code>（原始文本）、<code>out/plan_rows.json</code>（结构化）</div>"
        "</div>"
    )

    # A strict alignment table: one row per schedule row.
    table_rows: list[str] = []
    for row in rows:
        rid = esc(row["id"])
        rid_link = f"<a href=\"rows/{rid}.html\"><code>{rid}</code></a>"
        plan = esc(row.get("plan", ""))
        deliverables = row.get("deliverables") or []
        deliverables_html = "<br/>".join(f"• {esc(x)}" for x in deliverables) if deliverables else "<span class=\"small\">(none parsed)</span>"
        links = row.get("evidence_links") or []
        links_html = "<br/>".join(f"<code>{esc(p)}</code>" for p in links) if links else "<span class=\"badge warn\">TODO</span>"
        table_rows.append(
            "<tr>"
            f"<td>{rid_link}</td>"
            f"<td>{plan}</td>"
            f"<td>{deliverables_html}</td>"
            f"<td>{links_html}</td>"
            "</tr>"
        )

    body_parts.append(
        "<div class=\"card\">"
        "<h2>对齐表（每行计划 -> 证据链接）</h2>"
        "<table>"
        "<tr><th>周次</th><th>主要工作计划</th><th>预期产出（计划表）</th><th>当前证据（仓库内路径）</th></tr>"
        + "".join(table_rows)
        + "</table>"
        "</div>"
    )

    body_parts.append(
        "<div class=\"card\">"
        "<h2>原始抽取文本（便于复制到月报/周报）</h2>"
        f"<pre>{esc(text)}</pre>"
        "</div>"
    )

    write_text(out_dir / "report.html", html_page("00 计划对齐（进度计划表 -> evidence_steps 留痕）", "".join(body_parts)))

    # TODO list for rows without any evidence links.
    todo_lines: list[str] = []
    todo_lines.append(f"Generated at: {payload['generated_at']}")
    todo_lines.append(f"PDF: {payload['pdf']}")
    todo_lines.append("")
    todo_lines.append("Rows without evidence links (need evidence packs / docs / outputs):")
    for r in missing_rows:
        todo_lines.append(f"- {r['id']}: {r.get('plan','')}")
        for d in r.get("deliverables") or []:
            todo_lines.append(f"  - deliverable: {d}")
    todo_lines.append("")
    write_text(out_dir / "todo.md", "\n".join(todo_lines))

    print(f"Wrote {out_dir / 'report.html'}")
    print(f"Wrote {out_dir / 'plan_rows.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
