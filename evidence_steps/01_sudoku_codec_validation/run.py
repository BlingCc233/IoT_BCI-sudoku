#!/usr/bin/env python3
from __future__ import annotations

import json
import random
import subprocess
from pathlib import Path
from typing import Any

import sys

EVIDENCE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EVIDENCE_ROOT.parent
sys.path.append(str(EVIDENCE_ROOT / "_lib"))

from report import (  # noqa: E402
    esc,
    hexdump,
    html_page,
    now_local_str,
    render_bytes,
    render_sudoku_grid,
    svg_histogram,
    write_json,
    write_text,
)
from sudoku_layout import layout_custom  # noqa: E402


PERM4 = [
    (0, 1, 2, 3),
    (0, 1, 3, 2),
    (0, 2, 1, 3),
    (0, 2, 3, 1),
    (0, 3, 1, 2),
    (0, 3, 2, 1),
    (1, 0, 2, 3),
    (1, 0, 3, 2),
    (1, 2, 0, 3),
    (1, 2, 3, 0),
    (1, 3, 0, 2),
    (1, 3, 2, 0),
    (2, 0, 1, 3),
    (2, 0, 3, 1),
    (2, 1, 0, 3),
    (2, 1, 3, 0),
    (2, 3, 0, 1),
    (2, 3, 1, 0),
    (3, 0, 1, 2),
    (3, 0, 2, 1),
    (3, 1, 0, 2),
    (3, 1, 2, 0),
    (3, 2, 0, 1),
    (3, 2, 1, 0),
]


def pack_hints_to_key(h: list[int]) -> int:
    if len(h) != 4:
        raise ValueError("need 4 hints")
    a, b, c, d = (x & 0xFF for x in h)
    if a > b:
        a, b = b, a
    if c > d:
        c, d = d, c
    if a > c:
        a, c = c, a
    if b > d:
        b, d = d, b
    if b > c:
        b, c = c, b
    return (a << 24) | (b << 16) | (c << 8) | d


def run_go_dump(*, key: str, mode: str, pattern: str, out_path: Path) -> dict[str, Any]:
    cmd = [
        "go",
        "run",
        "./cmd/iotbci-evidence-sudoku-dump",
        "-key",
        key,
        "-mode",
        mode,
        "-pattern",
        pattern,
        "-out",
        str(out_path),
    ]
    p = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=180)
    if p.returncode != 0:
        raise RuntimeError(f"go dump failed ({p.returncode}):\n{p.stdout}\n{p.stderr}")
    return json.loads(out_path.read_text(encoding="utf-8"))


def run_go_tests() -> dict[str, object]:
    cmd = ["go", "test", "./pkg/obfs/sudoku", "-run", "TestCustomLayout", "-count=1"]
    try:
        p = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=180,
        )
        return {
            "cmd": cmd,
            "exit_code": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "cmd": cmd,
            "exit_code": None,
            "stdout": "",
            "stderr": f"failed to run go test: {e}",
        }


def decode_hint(layout, b: int) -> tuple[int, int] | None:
    group, ok = layout.decode_group(b & 0xFF)
    if not ok:
        return None
    value2b = (group >> 4) & 0x03
    pos4b = group & 0x0F
    return int(pos4b), int(value2b + 1)


def build_decode_map(encode_table: list[list[list[int]]]) -> dict[int, int]:
    out: dict[int, int] = {}
    for byte_val in range(256):
        for puzzle in encode_table[byte_val]:
            k = pack_hints_to_key([int(x) for x in puzzle])
            prev = out.get(k)
            if prev is not None and prev != byte_val:
                raise RuntimeError(f"decode-map collision: key=0x{k:08X} {prev} vs {byte_val}")
            out[k] = byte_val
    return out


def encode_with_trace(
    *,
    payload: bytes,
    encode_table: list[list[list[int]]],
    padding_pool: list[int],
    pad_rate: float,
    seed: int,
) -> tuple[bytes, list[dict[str, Any]]]:
    rng = random.Random(seed)
    pad_threshold = int(pad_rate * (2**32 - 1))

    def u32() -> int:
        return rng.getrandbits(32)

    def fast_index(n: int) -> int:
        # Same mapping strategy as Go: int(uint64(rng.Uint32()) * uint64(n) >> 32)
        # Here u32() is uniform but not the same RNG as Go's math/rand (acceptable for demonstration).
        return ((u32() * n) >> 32) if n > 1 else 0

    pads = list(padding_pool)
    if not pads:
        raise ValueError("empty padding pool")

    out: list[int] = []
    trace: list[dict[str, Any]] = []

    for i, b in enumerate(payload):
        b_int = int(b)
        step: dict[str, Any] = {"i": i, "byte": b_int, "pads_before": [], "pads_between": [], "pads_end": []}

        if u32() <= pad_threshold:
            pb = pads[fast_index(len(pads))]
            out.append(pb)
            step["pads_before"].append(pb)

        puzzles = encode_table[b_int]
        puzzle_idx = fast_index(len(puzzles))
        puzzle = puzzles[puzzle_idx]
        perm = PERM4[fast_index(len(PERM4))]

        step["puzzle_idx"] = puzzle_idx
        step["puzzle_hints_raw"] = [int(x) for x in puzzle]
        step["perm"] = list(perm)

        hinted: list[int] = []
        for idx in perm:
            pads_here: list[int] = []
            if u32() <= pad_threshold:
                pb = pads[fast_index(len(pads))]
                out.append(pb)
                pads_here.append(pb)
            hb = int(puzzle[idx]) & 0xFF
            out.append(hb)
            hinted.append(hb)
            step["pads_between"].append(pads_here)
        step["hints_wire_order"] = hinted

        trace.append(step)

    if u32() <= pad_threshold:
        pb = pads[fast_index(len(pads))]
        out.append(pb)

    return bytes(out), trace


def decode_with_trace(
    *,
    wire: bytes,
    layout,
    decode_map: dict[int, int],
) -> tuple[bytes, list[dict[str, Any]]]:
    buf: list[tuple[int, int]] = []
    out: list[int] = []
    groups: list[dict[str, Any]] = []

    for wi, b in enumerate(wire):
        bi = int(b) & 0xFF
        if not layout.is_hint(bi):
            continue
        buf.append((wi, bi))
        if len(buf) == 4:
            hints = [x[1] for x in buf]
            key = pack_hints_to_key(hints)
            if key not in decode_map:
                raise KeyError(f"map miss: key=0x{key:08X} hints={[f'0x{x:02X}' for x in hints]}")
            plain = decode_map[key]
            out.append(plain)
            groups.append(
                {
                    "wire_indexes": [x[0] for x in buf],
                    "hints_wire_order": hints,
                    "hints_sorted": sorted(hints),
                    "key_u32": key,
                    "decoded_byte": plain,
                }
            )
            buf.clear()

    if buf:
        raise ValueError(f"trailing {len(buf)} hint bytes without completing a group of 4")

    return bytes(out), groups


def bytes_hex(b: list[int]) -> str:
    return " ".join(f"{x:02x}" for x in b)


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    key = "seed-custom"
    mode = "prefer_entropy"
    patterns = ["xppppxvv", "vppxppvx"]

    pad_rate = 0.25
    demo_payload = b"BCI-SUDOKU|demo|" + bytes([0xAB, 0xAB, 0xAB, 0x00, 0xFF, 0x7F, 0x10, 0x11])
    seed_a = 0x11111111
    seed_b = 0x22222222

    go_test = run_go_tests()

    results: list[dict[str, Any]] = []
    cards: list[str] = []

    for pat in patterns:
        layout = layout_custom(pat)

        dump_path = out_dir / f"go_dump_{pat}.json"
        dump = run_go_dump(key=key, mode=mode, pattern=pat, out_path=dump_path)

        encode_table = dump["encode_table"]
        byte_to_grid = dump["byte_to_grid"]
        padding_pool = dump["padding_pool"]

        decode_map = build_decode_map(encode_table)

        wire_a, trace_a = encode_with_trace(
            payload=demo_payload,
            encode_table=encode_table,
            padding_pool=padding_pool,
            pad_rate=pad_rate,
            seed=seed_a,
        )
        wire_b, trace_b = encode_with_trace(
            payload=demo_payload,
            encode_table=encode_table,
            padding_pool=padding_pool,
            pad_rate=pad_rate,
            seed=seed_b,
        )

        dec_a, groups_a = decode_with_trace(wire=wire_a, layout=layout, decode_map=decode_map)
        dec_b, groups_b = decode_with_trace(wire=wire_b, layout=layout, decode_map=decode_map)

        ok_a = dec_a == demo_payload
        ok_b = dec_b == demo_payload
        differs = wire_a != wire_b

        puzzles_per_byte = [len(encode_table[i]) for i in range(256)]
        hist: dict[int, int] = {}
        for n in puzzles_per_byte:
            hist[n] = hist.get(n, 0) + 1

        # A focused “byte -> grid -> puzzle -> hints -> decode” walkthrough for 0xAB
        focus_byte = 0xAB
        focus_grid = byte_to_grid[focus_byte]
        focus_puzzles = encode_table[focus_byte]
        focus_hint_set = layout.hint_bytes()
        focus_pad_set = layout.padding_bytes()

        def render_puzzle(puzzle: list[int], *, title: str) -> str:
            decoded = [decode_hint(layout, int(x)) for x in puzzle]
            positions: set[int] = set()
            clues: dict[int, int] = {}
            for pv in decoded:
                if pv is None:
                    continue
                pos, _val = pv
                positions.add(pos)
                clues[pos] = _val
            puzzle_cells = [clues.get(i, "") for i in range(16)]
            rows = []
            for hb, pv in zip(puzzle, decoded):
                if pv is None:
                    rows.append(f"<tr><td><code>0x{int(hb):02X}</code></td><td colspan=\"3\">decode_group failed</td></tr>")
                    continue
                pos, val = pv
                rows.append(
                    "<tr>"
                    f"<td><code>0x{int(hb):02X}</code></td>"
                    f"<td>{pos}</td>"
                    f"<td>{val}</td>"
                    f"<td><code>{pos:04b}</code>/<code>{(val-1):02b}</code></td>"
                    "</tr>"
                )
            return (
                "<div class=\"card\">"
                f"<div class=\"small\">{esc(title)}</div>"
                + "<div class=\"small\">解（solution 4x4）</div>"
                + render_sudoku_grid(focus_grid, highlight_positions=positions)
                + "<div class=\"small\">题（puzzle，仅显示 4 个 clue）</div>"
                + render_sudoku_grid(puzzle_cells, highlight_positions=positions)
                + "<table>"
                "<tr><th>hint byte</th><th>pos</th><th>val</th><th>pos/val(bits)</th></tr>"
                + "".join(rows)
                + "</table>"
                "</div>"
            )

        focus_puzzle_0 = focus_puzzles[0]
        focus_puzzle_1 = focus_puzzles[1] if len(focus_puzzles) > 1 else focus_puzzles[0]

        # Demo: show two concrete encodings for the same payload
        def encoding_summary(wire: bytes) -> tuple[int, int, float]:
            hint_cnt = sum(1 for b in wire if layout.is_hint(int(b)))
            pad_cnt = len(wire) - hint_cnt
            overhead = (len(wire) / len(demo_payload)) if demo_payload else 0.0
            return hint_cnt, pad_cnt, overhead

        hint_a, pad_a, overhead_a = encoding_summary(wire_a)
        hint_b, pad_b, overhead_b = encoding_summary(wire_b)

        # Decode trace table (first K decoded bytes)
        def groups_table(groups: list[dict[str, Any]], *, k: int) -> str:
            rows = []
            for g in groups[:k]:
                rows.append(
                    "<tr>"
                    f"<td>{esc(g['decoded_byte'])} (<code>0x{int(g['decoded_byte']):02X}</code>)</td>"
                    f"<td><code>{esc(bytes_hex([int(x) for x in g['hints_wire_order']]))}</code></td>"
                    f"<td><code>{esc(bytes_hex([int(x) for x in g['hints_sorted']]))}</code></td>"
                    f"<td><code>0x{int(g['key_u32']):08X}</code></td>"
                    f"<td><code>{esc(g['wire_indexes'])}</code></td>"
                    "</tr>"
                )
            return (
                "<table>"
                "<tr><th>decoded byte</th><th>hints (wire order)</th><th>hints (sorted)</th><th>key</th><th>wire idx</th></tr>"
                + "".join(rows)
                + "</table>"
            )

        # Encoding trace table (per plaintext byte)
        def encode_trace_table(trace: list[dict[str, Any]]) -> str:
            rows = []
            for s in trace:
                b = int(s["byte"])
                hints = [int(x) for x in s["hints_wire_order"]]
                decoded = [decode_hint(layout, hb) for hb in hints]
                decoded_parts: list[str] = []
                for pv in decoded:
                    if pv is None:
                        continue
                    p, v = pv
                    decoded_parts.append(f"(pos={p},val={v})")
                decoded_str = ", ".join(decoded_parts)
                rows.append(
                    "<tr>"
                    f"<td>{s['i']}</td>"
                    f"<td><code>0x{b:02X}</code></td>"
                    f"<td>{b}</td>"
                    f"<td>{s['puzzle_idx']}</td>"
                    f"<td><code>{esc(s['perm'])}</code></td>"
                    f"<td><code>{esc(bytes_hex(hints))}</code><div class=\"small\">{esc(decoded_str)}</div></td>"
                    f"<td><code>{esc(bytes_hex([int(x) for x in s['pads_before']]))}</code></td>"
                    "</tr>"
                )
            return (
                "<table>"
                "<tr><th>i</th><th>byte(hex)</th><th>byte(dec)</th><th>puzzle#</th><th>perm</th><th>hints(out)</th><th>pads(before)</th></tr>"
                + "".join(rows)
                + "</table>"
            )

        puzzles_svg = svg_histogram(hist, title=f"#puzzles per byte — {layout.name}", bar_color="#a78bfa")

        mapping_details: list[str] = []
        for byte_val in range(256):
            grid = byte_to_grid[byte_val]
            puzzles_n = len(encode_table[byte_val])
            # show only first 2 puzzles to keep readable; full list exists in go_dump json.
            samples = encode_table[byte_val][:2]
            sample_html = ""
            if samples:
                rows = []
                for pi, puzzle in enumerate(samples):
                    decoded = [decode_hint(layout, int(x)) for x in puzzle]
                    decoded_parts: list[str] = []
                    for pv in decoded:
                        if pv is None:
                            continue
                        p, v = pv
                        decoded_parts.append(f"pos={p},val={v}")
                    decoded_s = ", ".join(decoded_parts)
                    rows.append(
                        "<tr>"
                        f"<td>{pi}</td>"
                        f"<td><code>{esc(bytes_hex([int(x) for x in puzzle]))}</code></td>"
                        f"<td class=\"small\">{esc(decoded_s)}</td>"
                        "</tr>"
                    )
                sample_html = (
                    "<table>"
                    "<tr><th>puzzle#</th><th>4 hints</th><th>decoded(pos,val)</th></tr>"
                    + "".join(rows)
                    + "</table>"
                )
            mapping_details.append(
                "<details>"
                f"<summary><code>0x{byte_val:02X}</code> -> 4x4 grid, puzzles={puzzles_n}</summary>"
                + render_sudoku_grid(grid)
                + sample_html
                + "</details>"
            )

        # Use the two traces to show randomness: does it pick different puzzle/perm for the same 0xAB bytes?
        chosen_a = [t for t in trace_a if int(t["byte"]) == focus_byte]
        chosen_b = [t for t in trace_b if int(t["byte"]) == focus_byte]

        cards.append(
            "<div class=\"card\">"
            f"<h2>{esc(layout.name)}</h2>"
            "<div class=\"small\">数据来源：<code>go run ./cmd/iotbci-evidence-sudoku-dump</code> 导出（与 Go 实现同一 EncodeTable + 同一 byte->grid shuffle）。</div>"
            "<div class=\"grid\">"
            f"<div class=\"card\">{puzzles_svg}</div>"
            "<div class=\"card\">"
            "<div class=\"small\">Hint/Pad 分类示例（随机编码输出首 256 字节，高亮）：</div>"
            + render_bytes(wire_a[:256], hint_bytes=focus_hint_set, pad_bytes=focus_pad_set, limit=256)
            + "</div>"
            "</div>"
            "<h2>1) Byte -> 4x4 Sudoku（全量映射，可展开）</h2>"
            "<div class=\"card\"><div class=\"small\">提示：浏览器内 <code>Ctrl/Cmd+F</code> 搜索 <code>0xAB</code> 可快速定位。</div>"
            + "".join(mapping_details)
            + "</div>"
            "<h2>2) 重点示例：0xAB 对应的 4x4 Sudoku + 两个不同题目（puzzle）</h2>"
            "<div class=\"grid\">"
            + render_puzzle(focus_puzzle_0, title="Puzzle sample #0 (4 hints in table order)")
            + render_puzzle(focus_puzzle_1, title="Puzzle sample #1 (4 hints in table order)")
            + "</div>"
            "<h2>3) 随机性示例：同一 payload 两次编码输出不同</h2>"
            "<table>"
            f"<tr><th>payload</th><td><code>{esc(demo_payload)}</code></td></tr>"
            f"<tr><th>seed A</th><td><code>0x{seed_a:08X}</code></td><th>seed B</th><td><code>0x{seed_b:08X}</code></td></tr>"
            f"<tr><th>wire A</th><td>{len(wire_a)} bytes (hint={hint_a}, pad={pad_a}, overhead={overhead_a:.2f}x)</td>"
            f"<th>wire B</th><td>{len(wire_b)} bytes (hint={hint_b}, pad={pad_b}, overhead={overhead_b:.2f}x)</td></tr>"
            f"<tr><th>wire differs?</th><td colspan=\"3\">{differs}</td></tr>"
            f"<tr><th>decode(A)==payload?</th><td>{ok_a}</td><th>decode(B)==payload?</th><td>{ok_b}</td></tr>"
            "</table>"
            "<div class=\"grid\">"
            "<div class=\"card\"><div class=\"small\">wire A hexdump (first 256 bytes)</div>"
            f"<pre>{esc(hexdump(wire_a[:256]))}</pre></div>"
            "<div class=\"card\"><div class=\"small\">wire B hexdump (first 256 bytes)</div>"
            f"<pre>{esc(hexdump(wire_b[:256]))}</pre></div>"
            "</div>"
            "<div class=\"card\">"
            "<div class=\"small\">编码过程追踪（seed A；每个 plaintext byte 的 puzzle/perm/hints）。</div>"
            + encode_trace_table(trace_a)
            + "</div>"
            "<div class=\"card\">"
            "<div class=\"small\">解码过程追踪（seed A；前 16 个 decoded bytes）。</div>"
            + groups_table(groups_a, k=16)
            + "</div>"
            "<div class=\"card\">"
            "<div class=\"small\">同一 byte(0xAB) 在两次编码中被选择的 puzzle/perm（用于展示随机差异）。</div>"
            "<table>"
            "<tr><th>run</th><th>#occurrences</th><th>puzzle_idx list</th><th>perm list</th></tr>"
            f"<tr><td>seed A</td><td>{len(chosen_a)}</td><td><code>{esc([c['puzzle_idx'] for c in chosen_a])}</code></td>"
            f"<td><code>{esc([c['perm'] for c in chosen_a])}</code></td></tr>"
            f"<tr><td>seed B</td><td>{len(chosen_b)}</td><td><code>{esc([c['puzzle_idx'] for c in chosen_b])}</code></td>"
            f"<td><code>{esc([c['perm'] for c in chosen_b])}</code></td></tr>"
            "</table>"
            "</div>"
            "<div class=\"small\">导出：<code>"
            + esc(str(dump_path.relative_to(REPO_ROOT)))
            + "</code>（包含全量 EncodeTable 与 byte->grid）。</div>"
            "</div>"
        )

        results.append(
            {
                "pattern": pat,
                "key": key,
                "mode": mode,
                "pad_rate": pad_rate,
                "demo": {
                    "payload_len": len(demo_payload),
                    "wire_a_len": len(wire_a),
                    "wire_b_len": len(wire_b),
                    "wire_differs": differs,
                    "decode_a_ok": ok_a,
                    "decode_b_ok": ok_b,
                },
                "stats": dump.get("stats", {}),
                "go_dump": str(dump_path.relative_to(REPO_ROOT)),
            }
        )

    summary = {
        "generated_at": now_local_str(),
        "go_test": go_test,
        "results": results,
    }
    write_json(out_dir / "summary.json", summary)

    go_badge = "ok" if go_test.get("exit_code") == 0 else "fail"
    go_badge_text = "PASS" if go_badge == "ok" else "FAIL"
    go_block = (
        "<div class=\"card\">"
        f"<h2>Go 对照单测 <span class=\"badge {go_badge}\">{go_badge_text}</span></h2>"
        "<div class=\"small\"><code>"
        + esc(" ".join(go_test.get("cmd", [])))
        + "</code></div>"
        f"<pre>{esc((go_test.get('stdout') or '') + (go_test.get('stderr') or ''))}</pre>"
        "</div>"
    )

    body = (
        "<h1>01 数独编解码验证（Python + Go 导出对齐）</h1>"
        "<div class=\"card\">"
        "<div class=\"small\">本报告目标：对齐 Go 实现的 EncodeTable/byte->grid，并用可视化把编解码过程（puzzle 选择/乱序/padding/解码）讲清楚，便于月报截图与复核。</div>"
        "<table>"
        f"<tr><th>go dump tool</th><td><code>cmd/iotbci-evidence-sudoku-dump</code></td></tr>"
        f"<tr><th>key</th><td><code>{esc(key)}</code></td></tr>"
        f"<tr><th>mode</th><td><code>{esc(mode)}</code></td></tr>"
        f"<tr><th>pad_rate</th><td>{pad_rate:.2f}</td></tr>"
        f"<tr><th>demo payload</th><td><code>{esc(demo_payload)}</code></td></tr>"
        "</table>"
        "</div>"
        + "".join(cards)
        + go_block
    )
    write_text(out_dir / "report.html", html_page("01 数独编解码验证（Python + Go 导出对齐）", body))

    print(f"Wrote {out_dir / 'report.html'}")
    print(f"Wrote {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
