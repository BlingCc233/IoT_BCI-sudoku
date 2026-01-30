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
    svg_histogram,
    write_json,
    write_text,
)
from sudoku_layout import layouts_for_report  # noqa: E402


def hamming8(a: int, b: int) -> int:
    return popcount8((a ^ b) & 0xFF)


def min_hamming_to_set(b: int, s: set[int]) -> int:
    return min(hamming8(b, x) for x in s) if s else 8


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    patterns = ["xppppxvv", "vppxppvx"]
    layouts = layouts_for_report(patterns)

    summary: dict[str, object] = {
        "generated_at": now_local_str(),
        "patterns": patterns,
        "layouts": [],
    }

    pair_lines: list[str] = []
    cards: list[str] = []

    for layout in layouts:
        hint_set = layout.hint_bytes()
        pad_set = layout.padding_bytes()

        pad_min_dist_hist: dict[int, int] = {}
        for b in pad_set:
            d = min_hamming_to_set(b, hint_set)
            pad_min_dist_hist[d] = pad_min_dist_hist.get(d, 0) + 1

        hint_min_dist_hist: dict[int, int] = {}
        for b in hint_set:
            d = min_hamming_to_set(b, pad_set)
            hint_min_dist_hist[d] = hint_min_dist_hist.get(d, 0) + 1

        # Distance-1 pairs (hint <-> padding).
        dist1_pairs: list[tuple[int, int]] = []
        for p in sorted(pad_set):
            for h in sorted(hint_set):
                if hamming8(p, h) == 1:
                    dist1_pairs.append((h, p))

        # Within-hint distance distribution (pairwise).
        hint_list = sorted(hint_set)
        hint_pair_hist: dict[int, int] = {}
        for i in range(len(hint_list)):
            for j in range(i + 1, len(hint_list)):
                d = hamming8(hint_list[i], hint_list[j])
                hint_pair_hist[d] = hint_pair_hist.get(d, 0) + 1

        # One-bit flip to hint analysis.
        pad_flip_to_hint_hist: dict[int, int] = {}
        for p in pad_set:
            to_hint = 0
            for bit in range(8):
                if layout.is_hint(p ^ (1 << bit)):
                    to_hint += 1
            pad_flip_to_hint_hist[to_hint] = pad_flip_to_hint_hist.get(to_hint, 0) + 1

        summary["layouts"].append(
            {
                "name": layout.name,
                "hint_bytes_count": len(hint_set),
                "padding_bytes_count": len(pad_set),
                "pad_min_dist_to_hint_hist": pad_min_dist_hist,
                "hint_min_dist_to_padding_hist": hint_min_dist_hist,
                "hint_pairwise_dist_hist": hint_pair_hist,
                "distance1_pairs_count": len(dist1_pairs),
                "padding_onebit_flip_to_hint_hist": pad_flip_to_hint_hist,
                "distance1_pairs_sample": [{"hint": f"0x{h:02X}", "padding": f"0x{p:02X}"} for h, p in dist1_pairs[:20]],
            }
        )

        pair_lines.append(f"== {layout.name} ==")
        pair_lines.append(f"distance-1 pairs (hint -> padding): {len(dist1_pairs)}")
        for h, p in dist1_pairs[:80]:
            pair_lines.append(f"  hint 0x{h:02X} ({h:08b})  <->  pad 0x{p:02X} ({p:08b})")
        pair_lines.append("")

        pad_svg = svg_histogram(pad_min_dist_hist, title=f"Min dist(padding -> hint) — {layout.name}", bar_color="#60a5fa")
        hint_svg = svg_histogram(hint_min_dist_hist, title=f"Min dist(hint -> padding) — {layout.name}", bar_color="#a78bfa")
        hint_pair_svg = svg_histogram(hint_pair_hist, title=f"Pairwise dist(hint, hint) — {layout.name}", bar_color="#34d399")
        flip_svg = svg_histogram(
            pad_flip_to_hint_hist,
            title=f"#(1-bit flips that become hint) — {layout.name}",
            bar_color="#f59e0b",
        )

        sample_rows = "".join(
            "<tr>"
            f"<td><code>0x{h:02X}</code></td>"
            f"<td><code>0x{p:02X}</code></td>"
            f"<td><code>{h:08b}</code></td>"
            f"<td><code>{p:08b}</code></td>"
            f"<td>{hamming8(h, p)}</td>"
            "</tr>"
            for h, p in dist1_pairs[:12]
        )
        sample_table = (
            "<table>"
            "<tr><th>hint</th><th>padding</th><th>hint(bin)</th><th>pad(bin)</th><th>Hamming</th></tr>"
            + (sample_rows if sample_rows else "<tr><td colspan=\"5\" class=\"small\">(no distance-1 pairs)</td></tr>")
            + "</table>"
        )

        cards.append(
            "<div class=\"card\">"
            f"<h2>{esc(layout.name)}</h2>"
            "<div class=\"small\">"
            "解读要点：<br/>"
            "1) <b>Min dist(padding -> hint)</b> 越大，padding 越不可能在“单/少数位变化”后被误判为 hint。<br/>"
            "2) <b>distance-1 pairs</b> 表示存在 padding 与 hint 仅差 1 bit：在比特翻转/主动篡改下更容易触发误判。<br/>"
            "3) 解码器遇到 map miss 会返回错误并触发可疑流量路径（详见 Go 实现中的 <code>ErrInvalidSudokuMapMiss</code>）。"
            "</div>"
            "<table>"
            f"<tr><th>#hint</th><td>{len(hint_set)}</td><th>#padding</th><td>{len(pad_set)}</td></tr>"
            f"<tr><th>distance-1 pairs</th><td colspan=\"3\">{len(dist1_pairs)}</td></tr>"
            "</table>"
            "<div class=\"grid\">"
            f"<div class=\"card\">{pad_svg}</div>"
            f"<div class=\"card\">{hint_svg}</div>"
            f"<div class=\"card\">{hint_pair_svg}</div>"
            f"<div class=\"card\">{flip_svg}</div>"
            "</div>"
            "<div class=\"small\">distance=1 pairs sample:</div>"
            f"{sample_table}"
            "</div>"
        )

    write_json(out_dir / "summary.json", summary)
    write_text(out_dir / "distance1_pairs.txt", "\n".join(pair_lines).rstrip() + "\n")

    # Copy-friendly summary
    lines: list[str] = []
    lines.append(f"Generated at: {summary['generated_at']}")
    lines.append(f"Patterns: {', '.join(patterns)}")
    lines.append("")
    for item in summary["layouts"]:
        name = item["name"]
        dist1 = item["distance1_pairs_count"]
        lines.append(f"- {name}: distance1_pairs={dist1}")
        lines.append(f"  pad_min_dist_to_hint_hist={item['pad_min_dist_to_hint_hist']}")
        lines.append(f"  padding_onebit_flip_to_hint_hist={item['padding_onebit_flip_to_hint_hist']}")
    lines.append("")
    write_text(out_dir / "summary.txt", "\n".join(lines))

    body = (
        "<h1>03 汉明距离（Hamming-1）分析工具</h1>"
        "<div class=\"card\">"
        "<div class=\"small\">"
        "关注点：<br/>"
        "1) padding 到 hint 的最小汉明距离分布（越大越安全）；<br/>"
        "2) 距离=1 的 padding/hint 对（表示 1-bit 变化就可能跨越 isHint 判定边界）；<br/>"
        "3) padding 单比特翻转后变成 hint 的可能性（每个 padding byte 有多少个 bit 翻转能变成 hint）。"
        "<br/><br/>"
        "备注：在正常 TCP + AEAD 语境下，bit flip 不应无声发生；该分析主要用于说明鲁棒性边界与异常/攻击触发面。"
        "</div>"
        "<table>"
        "<tr><th>custom patterns</th><td><code>"
        + esc(", ".join(patterns))
        + "</code></td></tr>"
        "</table>"
        "</div>"
        + "".join(cards)
    )
    write_text(out_dir / "report.html", html_page("03 汉明距离（Hamming-1）分析工具", body))

    print(f"Wrote {out_dir / 'report.html'}")
    print(f"Wrote {out_dir / 'distance1_pairs.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
