#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "_lib"))

from report import (  # noqa: E402
    esc,
    html_page,
    now_local_str,
    popcount8,
    svg_byte_grid,
    svg_histogram,
    write_json,
    write_text,
)
from sudoku_layout import layouts_for_report  # noqa: E402


def fmt_hex(b: int) -> str:
    return f"0x{b & 0xFF:02X}"


def layout_explain(name: str) -> str:
    if name == "ascii":
        return (
            "ASCII layout：用 <code>hintMask=0x40</code> 标记 hint（bit6=1）。"
            "padding 取 <code>0x20..0x3F</code>（可打印字符）。"
            "实现中 <code>\\n</code>(0x0A) 作为 0x7F 的 on-wire alias，也会被识别为 hint。"
        )
    if name == "entropy":
        return (
            "Entropy layout：<code>hintMask=0x90</code> 且 <code>hintValue=0x00</code>，"
            "即 bit7 与 bit4 必须为 0 才可能是 hint。padding pool 取两个 byte 区间混合，"
            "用于拉开字节分布、降低简单特征。"
        )
    if name.startswith("custom("):
        return (
            "Custom x/v/p layout：hint 的必要条件是 2 个 x 位都为 1（形成 <code>hintMask</code>）。"
            "padding pool 通过“丢掉 1 个 x 位”构造，确保 padding 永远不会被误判为 hint；"
            "并施加 popcount>=5 约束，使 padding 看起来更“忙”。"
        )
    return ""


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    patterns = ["xppppxvv", "vppxppvx"]
    layouts = layouts_for_report(patterns)

    summary = {
        "generated_at": now_local_str(),
        "patterns": patterns,
        "layouts": [],
    }

    cards: list[str] = []
    for layout in layouts:
        hint_set = layout.hint_bytes()
        pad_set = layout.padding_bytes()
        overlap = len(hint_set & pad_set)

        hint_ok = all(layout.is_hint(b) for b in hint_set)
        pad_ok = not any(layout.is_hint(b) for b in pad_set)

        pad_weights = [popcount8(b) for b in pad_set]
        hint_weights = [popcount8(b) for b in hint_set]

        pad_hist: dict[int, int] = {}
        for w in pad_weights:
            pad_hist[w] = pad_hist.get(w, 0) + 1

        hint_hist: dict[int, int] = {}
        for w in hint_weights:
            hint_hist[w] = hint_hist.get(w, 0) + 1

        pad_min = min(pad_weights) if pad_weights else None
        pad_max = max(pad_weights) if pad_weights else None
        pad_avg = (sum(pad_weights) / len(pad_weights)) if pad_weights else None

        hint_min = min(hint_weights) if hint_weights else None
        hint_max = max(hint_weights) if hint_weights else None
        hint_avg = (sum(hint_weights) / len(hint_weights)) if hint_weights else None

        summary["layouts"].append(
            {
                "name": layout.name,
                "hint_mask": fmt_hex(layout.hint_mask),
                "hint_value": fmt_hex(layout.hint_value),
                "hint_bytes_count": len(hint_set),
                "padding_pool_count": len(layout.padding_pool),
                "padding_unique_count": len(pad_set),
                "hint_padding_overlap": overlap,
                "hint_validation_ok": hint_ok,
                "padding_validation_ok": pad_ok,
                "hint_popcount": {"min": hint_min, "avg": hint_avg, "max": hint_max, "hist": hint_hist},
                "padding_popcount": {"min": pad_min, "avg": pad_avg, "max": pad_max, "hist": pad_hist},
                "padding_pool_first_32_hex": [fmt_hex(b) for b in layout.padding_pool[:32]],
            }
        )

        badge = "ok" if (hint_ok and pad_ok) else "fail"
        badge_text = "PASS" if badge == "ok" else "FAIL"

        grid_svg = svg_byte_grid(
            title=f"0..255 byte space — {layout.name}",
            hint_set=hint_set,
            pad_set=pad_set,
        )
        pad_hist_svg = svg_histogram(pad_hist, title=f"Padding popcount histogram — {layout.name}", bar_color="#60a5fa")
        hint_hist_svg = svg_histogram(hint_hist, title=f"Hint popcount histogram — {layout.name}", bar_color="#a78bfa")

        cards.append(
            "<div class=\"card\">"
            f"<h2>{esc(layout.name)} <span class=\"badge {badge}\">{badge_text}</span></h2>"
            f"<div class=\"small\">{layout_explain(layout.name)}</div>"
            "<table>"
            "<tr><th>hintMask</th><td><code>"
            f"{esc(fmt_hex(layout.hint_mask))}"
            "</code></td><th>hintValue</th><td><code>"
            f"{esc(fmt_hex(layout.hint_value))}"
            "</code></td></tr>"
            "<tr><th>#hint bytes</th><td>"
            f"{len(hint_set)}"
            "</td><th>#padding bytes</th><td>"
            f"{len(pad_set)}"
            "</td></tr>"
            "<tr><th>overlap(hint∩padding)</th><td colspan=\"3\">"
            f"{overlap}"
            "</td></tr>"
            "<tr><th>padding popcount</th><td>"
            f"min={pad_min}, avg={pad_avg:.2f}, max={pad_max}"
            "</td><th>hint popcount</th><td>"
            f"min={hint_min}, avg={hint_avg:.2f}, max={hint_max}"
            "</td></tr>"
            "<tr><th>checks</th><td colspan=\"3\">"
            f"all(hint -> isHint)={hint_ok}; all(padding -> !isHint)={pad_ok}"
            "</td></tr>"
            "</table>"
            "<div class=\"grid\">"
            f"<div class=\"card\">{grid_svg}</div>"
            f"<div class=\"card\">{pad_hist_svg}</div>"
            f"<div class=\"card\">{hint_hist_svg}</div>"
            "</div>"
            "<div class=\"small\">padding pool (first 32 bytes):</div>"
            "<pre>"
            + " ".join(f"{b:02x}" for b in layout.padding_pool[:32])
            + "</pre>"
            "</div>"
        )

    body = (
        "<h1>02 Padding + 自定义字节格式（x/v/p）验证</h1>"
        "<div class=\"card\">"
        "<div class=\"small\">"
        "目标：用可视化 + 统计证明 <b>hint 与 padding 在字节层面可分离</b>，即解码端可通过 <code>isHint</code> 跳过 padding，"
        "只收集 hint 进行 4-hint 组装与查表解码。"
        "<br/>"
        "判定标准：<code>overlap(hint∩padding)=0</code> 且 <code>all(padding -> !isHint)=True</code>。"
        "</div>"
        "<table>"
        "<tr><th>custom patterns</th><td><code>"
        + esc(", ".join(patterns))
        + "</code></td></tr>"
        "</table>"
        "</div>"
        + "".join(cards)
    )

    write_json(out_dir / "summary.json", summary)

    # A copy-friendly plain-text summary for monthly reports.
    lines: list[str] = []
    lines.append(f"Generated at: {summary['generated_at']}")
    lines.append(f"Patterns: {', '.join(patterns)}")
    lines.append("")
    for item in summary["layouts"]:
        lines.append(f"- {item['name']}:")
        lines.append(
            f"  hintMask={item['hint_mask']} hintValue={item['hint_value']} "
            f"#hint={item['hint_bytes_count']} #padding={item['padding_unique_count']} "
            f"overlap={item['hint_padding_overlap']} "
            f"checks(hint={item['hint_validation_ok']}, padding={item['padding_validation_ok']})"
        )
        lines.append(
            "  padding popcount: "
            f"min={item['padding_popcount']['min']} avg={item['padding_popcount']['avg']:.2f} "
            f"max={item['padding_popcount']['max']}"
        )
    lines.append("")
    write_text(out_dir / "summary.txt", "\n".join(lines))

    write_text(out_dir / "report.html", html_page("02 Padding + 自定义字节格式（x/v/p）验证", body))

    print(f"Wrote {out_dir / 'report.html'}")
    print(f"Wrote {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
