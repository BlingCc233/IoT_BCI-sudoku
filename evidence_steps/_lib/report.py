from __future__ import annotations

import datetime as _dt
import html as _html
import json as _json
from pathlib import Path
from typing import Iterable, Mapping


def now_local_str() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(path: Path, obj: object) -> None:
    write_text(path, _json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def esc(s: object) -> str:
    return _html.escape(str(s), quote=True)


_CSS = r"""
:root{
  --bg:#ffffff;
  --card:#ffffff;
  --text:#111827;
  --muted:#6b7280;
  --accent:#2563eb;
  --ok:#16a34a;
  --bad:#dc2626;
  --warn:#f59e0b;
  --border:#e5e7eb;
  --chip:#f3f4f6;
  --shadow:0 6px 18px rgba(17,24,39,.08);
  --mono:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  --hint:#6d28d9;
  --pad:#0ea5e9;
  --other:#cbd5e1;

  /* Protocol palette (aligned with cmd/iotbci-dashboard). */
  --sudoku:#6d28d9;
  --sudoku2:#a78bfa;
  --coap:#16a34a;
  --aead:#0ea5e9;
  --dtls:#f97316;
  --mqtt:#ef4444;
  --protoOther:#64748b;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;line-height:1.45}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.container{max-width:1180px;margin:0 auto;padding:20px 20px 48px}
h1{font-size:20px;margin:8px 0 10px;letter-spacing:.2px}
h2{font-size:16px;margin:0 0 10px}
.small{color:var(--muted);font-size:12px}
.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;margin:14px 0;box-shadow:var(--shadow)}
pre,code{font-family:var(--mono)}
pre{background:#f9fafb;border:1px solid var(--border);padding:12px;border-radius:12px;overflow:auto}
code{background:rgba(17,24,39,.04);border:1px solid rgba(17,24,39,.06);padding:2px 6px;border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:12px}
th,td{border:1px solid var(--border);padding:8px 10px;vertical-align:top}
th{text-align:left;background:#f9fafb;color:#374151}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:12px}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;border:1px solid var(--border);background:var(--chip);color:var(--text)}
.badge.ok{color:var(--ok)}
.badge.fail{color:var(--bad)}
.badge.warn{color:var(--warn)}
.bytes{line-height:1.9}
.byte{display:inline-block;font-family:var(--mono);padding:1px 6px;border-radius:8px;margin:1px 2px 1px 0;border:1px solid var(--border);background:rgba(17,24,39,.02)}
.byte.hint{background:rgba(109,40,217,.10);border-color:rgba(109,40,217,.28)}
.byte.pad{background:rgba(14,165,233,.10);border-color:rgba(14,165,233,.28)}
.byte.other{background:rgba(17,24,39,.02)}
.sudoku-grid{border-collapse:separate;border-spacing:4px;margin:6px 0}
.sudoku-grid td{width:32px;height:32px;text-align:center;font-family:var(--mono);font-size:13px;background:#f9fafb;border:1px solid var(--border);border-radius:10px}
.sudoku-grid td.hl{background:rgba(109,40,217,.10);border-color:rgba(109,40,217,.28)}
svg{max-width:100%;height:auto}
"""


def html_page(title: str, body_html: str, *, generated_at: str | None = None) -> str:
    ts = generated_at or now_local_str()
    return (
        "<!doctype html>\n"
        "<html lang=\"zh-CN\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\" />\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n"
        f"  <title>{esc(title)}</title>\n"
        f"  <style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        "  <div class=\"container\">\n"
        f"    <div class=\"small\">Generated at {esc(ts)}</div>\n"
        f"    {body_html}\n"
        "  </div>\n"
        "</body>\n"
        "</html>\n"
    )


_POPCOUNT = [bin(i).count("1") for i in range(256)]


def popcount8(b: int) -> int:
    return _POPCOUNT[b & 0xFF]


def hexdump(data: bytes, *, width: int = 16) -> str:
    out_lines: list[str] = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hex_part = " ".join(f"{x:02x}" for x in chunk)
        asc_part = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        out_lines.append(f"{off:08x}  {hex_part:<{width*3}}  |{asc_part}|")
    return "\n".join(out_lines) + ("\n" if out_lines else "")


def render_bytes(
    data: bytes,
    *,
    hint_bytes: Iterable[int],
    pad_bytes: Iterable[int],
    limit: int = 512,
) -> str:
    hint_set = {b & 0xFF for b in hint_bytes}
    pad_set = {b & 0xFF for b in pad_bytes}
    parts: list[str] = ["<div class=\"bytes\">"]
    shown = data[:limit]
    for b in shown:
        cls = "other"
        if b in hint_set:
            cls = "hint"
        elif b in pad_set:
            cls = "pad"
        parts.append(f"<span class=\"byte {cls}\">{b:02x}</span>")
    if len(data) > limit:
        parts.append(f"<span class=\"small\">… ({len(data) - limit} bytes truncated)</span>")
    parts.append("</div>")
    return "".join(parts)


def render_sudoku_grid(values: Iterable[int], *, highlight_positions: set[int] | None = None) -> str:
    vals = list(values)
    if len(vals) != 16:
        raise ValueError(f"expected 16 cells, got {len(vals)}")
    hl = highlight_positions or set()

    parts: list[str] = ["<table class=\"sudoku-grid\">"]
    for r in range(4):
        parts.append("<tr>")
        for c in range(4):
            idx = r * 4 + c
            v = vals[idx]
            cls = "hl" if idx in hl else ""
            parts.append(f"<td class=\"{cls}\" title=\"pos {idx}\">{esc(v)}</td>")
        parts.append("</tr>")
    parts.append("</table>")
    return "".join(parts)


def svg_byte_grid(
    *,
    title: str,
    hint_set: set[int],
    pad_set: set[int],
    cell: int = 14,
    margin: int = 18,
) -> str:
    # 16x16 grid for 0..255
    w = margin + 16 * cell + 10
    h = margin + 16 * cell + 46
    hint = {b & 0xFF for b in hint_set}
    pad = {b & 0xFF for b in pad_set}

    def color(b: int) -> str:
        if b in hint:
            return "var(--hint)"
        if b in pad:
            return "var(--pad)"
        return "var(--other)"

    rects: list[str] = []
    for b in range(256):
        x = margin + (b % 16) * cell
        y = margin + (b // 16) * cell
        rects.append(
            f"<rect x=\"{x}\" y=\"{y}\" width=\"{cell-1}\" height=\"{cell-1}\" "
            f"fill=\"{color(b)}\" rx=\"2\" />"
        )

    legend_y = margin + 16 * cell + 14
    legend = (
        f"<rect x=\"{margin}\" y=\"{legend_y}\" width=\"10\" height=\"10\" fill=\"var(--hint)\" rx=\"2\" />"
        f"<text x=\"{margin+14}\" y=\"{legend_y+9}\" fill=\"var(--muted)\" font-size=\"12\">hint</text>"
        f"<rect x=\"{margin+70}\" y=\"{legend_y}\" width=\"10\" height=\"10\" fill=\"var(--pad)\" rx=\"2\" />"
        f"<text x=\"{margin+84}\" y=\"{legend_y+9}\" fill=\"var(--muted)\" font-size=\"12\">padding</text>"
        f"<rect x=\"{margin+170}\" y=\"{legend_y}\" width=\"10\" height=\"10\" fill=\"var(--other)\" rx=\"2\" />"
        f"<text x=\"{margin+184}\" y=\"{legend_y+9}\" fill=\"var(--muted)\" font-size=\"12\">other</text>"
    )
    return (
        f"<svg viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"{esc(title)}\" "
        "xmlns=\"http://www.w3.org/2000/svg\">"
        f"<text x=\"{margin}\" y=\"14\" fill=\"var(--text)\" font-size=\"13\">{esc(title)}</text>"
        + "".join(rects)
        + legend
        + "</svg>"
    )


def svg_histogram(
    counts: Mapping[int, int],
    *,
    title: str,
    bar_color: str = "var(--pad)",
    width: int = 640,
    height: int = 220,
) -> str:
    bins = sorted(counts.keys())
    if not bins:
        bins = [0]
        counts = {0: 0}

    max_v = max(counts.values()) or 1
    left = 44
    top = 18
    bottom = 32
    right = 16
    plot_w = width - left - right
    plot_h = height - top - bottom
    bw = max(10, int(plot_w / max(1, len(bins))))
    gap = 4
    bw_eff = max(6, bw - gap)

    bars: list[str] = []
    labels: list[str] = []
    for i, b in enumerate(bins):
        v = counts.get(b, 0)
        h = int(plot_h * (v / max_v))
        x = left + i * bw + gap // 2
        y = top + (plot_h - h)
        bars.append(f"<rect x=\"{x}\" y=\"{y}\" width=\"{bw_eff}\" height=\"{h}\" fill=\"{bar_color}\" rx=\"3\" />")
        labels.append(
            f"<text x=\"{x + bw_eff/2}\" y=\"{top + plot_h + 18}\" text-anchor=\"middle\" "
            f"fill=\"var(--muted)\" font-size=\"12\">{esc(b)}</text>"
        )

    y0 = top + plot_h
    axes = (
        f"<line x1=\"{left}\" y1=\"{top}\" x2=\"{left}\" y2=\"{y0}\" stroke=\"rgba(17,24,39,.14)\" />"
        f"<line x1=\"{left}\" y1=\"{y0}\" x2=\"{width-right}\" y2=\"{y0}\" stroke=\"rgba(17,24,39,.14)\" />"
        f"<text x=\"{left}\" y=\"14\" fill=\"var(--text)\" font-size=\"13\">{esc(title)}</text>"
        f"<text x=\"{left-8}\" y=\"{top+10}\" text-anchor=\"end\" fill=\"var(--muted)\" font-size=\"11\">{esc(max_v)}</text>"
        f"<text x=\"{left-8}\" y=\"{y0}\" text-anchor=\"end\" fill=\"var(--muted)\" font-size=\"11\">0</text>"
    )
    return (
        f"<svg viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"{esc(title)}\" "
        "xmlns=\"http://www.w3.org/2000/svg\">"
        + axes
        + "".join(bars)
        + "".join(labels)
        + "</svg>"
    )
