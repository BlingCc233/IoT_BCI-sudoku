#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import math
import random
import statistics
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import sys

EVIDENCE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EVIDENCE_ROOT.parent
sys.path.append(str(EVIDENCE_ROOT / "_lib"))

from report import esc, html_page, now_local_str, write_json, write_text  # noqa: E402


def run_cmd(cmd: list[str], *, timeout_s: int = 1200) -> dict[str, Any]:
    started = time.monotonic()
    try:
        p = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=timeout_s)
        return {
            "cmd": cmd,
            "exit_code": p.returncode,
            "duration_s": time.monotonic() - started,
            "stdout": p.stdout,
            "stderr": p.stderr,
        }
    except Exception as e:  # noqa: BLE001
        return {
            "cmd": cmd,
            "exit_code": None,
            "duration_s": time.monotonic() - started,
            "stdout": "",
            "stderr": f"failed: {e}",
        }


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def fmt_num(x: float, digits: int = 4) -> str:
    if math.isnan(x) or math.isinf(x):
        return str(x)
    return f"{x:.{digits}f}"


def entropy_bits_per_byte(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c <= 0:
            continue
        p = c / n
        ent -= p * math.log2(p)
    return ent


def ascii_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = sum(1 for b in data if 0x20 <= b <= 0x7E)
    return cnt / len(data)


def safe_mean(v: list[float | int]) -> float:
    if not v:
        return 0.0
    return float(statistics.mean(float(x) for x in v))


def safe_std(v: list[float | int]) -> float:
    if len(v) <= 1:
        return 0.0
    return float(statistics.pstdev(float(x) for x in v))


def fixed_window(seq: list[int], n: int) -> list[float]:
    s = [float(x) for x in seq[:n]]
    if len(s) < n:
        s.extend([0.0] * (n - len(s)))
    return s


def chunk_means(seq: list[float], chunks: int) -> list[float]:
    if chunks <= 0:
        return []
    if not seq:
        return [0.0] * chunks
    out: list[float] = []
    step = max(1, len(seq) // chunks)
    for i in range(chunks):
        part = seq[i * step : (i + 1) * step]
        out.append(safe_mean(part))
    while len(out) < chunks:
        out.append(0.0)
    return out[:chunks]


def feature_from_metrics(m: dict[str, Any]) -> list[float]:
    sz_seq = [int(x) for x in (m.get("wire_write_size_seq_sample") or [])]
    iat_seq = [int(x) for x in (m.get("wire_write_interarrival_ms_seq_sample") or [])]
    s = fixed_window(sz_seq, 128)
    t = fixed_window(iat_seq, 128)
    return [
        float(m.get("overhead_ratio", 0.0)),
        float(m.get("wire_entropy", 0.0)),
        float(m.get("wire_ascii_ratio", 0.0)),
        float(m.get("wire_write_calls", 0.0)),
        float(m.get("wire_read_calls", 0.0)),
        safe_mean(s),
        safe_std(s),
        safe_mean(t),
        safe_std(t),
        *chunk_means(s, 12),
        *chunk_means(t, 8),
    ]


def class_feature_from_metrics(m: dict[str, Any]) -> list[float]:
    # Side-channel attacker only sees packet-length sequence (no protocol internals).
    sz_seq = [int(x) for x in (m.get("wire_write_size_seq_sample") or [])]
    s = fixed_window(sz_seq, 128)
    return [
        safe_mean(s),
        safe_std(s),
        max(s) if s else 0.0,
        min(s) if s else 0.0,
        *chunk_means(s, 16),
    ]


@dataclass
class LabeledSample:
    label: str
    vector: list[float]
    meta: dict[str, Any]


def dist2(a: list[float], b: list[float]) -> float:
    return sum((x - y) * (x - y) for x, y in zip(a, b))


def nearest_centroid_loo(samples: list[LabeledSample]) -> dict[str, Any]:
    labels = sorted({s.label for s in samples})
    matrix: dict[str, dict[str, int]] = {a: {b: 0 for b in labels} for a in labels}
    if not samples:
        return {"labels": labels, "matrix": matrix, "accuracy": 0.0}

    ok = 0
    for i, s in enumerate(samples):
        train = [x for j, x in enumerate(samples) if j != i]
        centroids: dict[str, list[float]] = {}
        for c in labels:
            rows = [x.vector for x in train if x.label == c]
            if not rows:
                continue
            d = len(rows[0])
            sums = [0.0] * d
            for r in rows:
                for k, v in enumerate(r):
                    sums[k] += v
            centroids[c] = [v / len(rows) for v in sums]
        if not centroids:
            continue
        pred = min(centroids.keys(), key=lambda c: dist2(s.vector, centroids[c]))
        matrix[s.label][pred] += 1
        if pred == s.label:
            ok += 1
    return {"labels": labels, "matrix": matrix, "accuracy": ok / len(samples)}


def svg_confusion_matrix(matrix: dict[str, dict[str, int]], labels: list[str], *, title: str) -> str:
    n = len(labels)
    if n == 0:
        return ""
    cell = 56
    left = 180
    top = 60
    width = left + cell * n + 20
    height = top + cell * n + 40

    vmax = 1
    for a in labels:
        for b in labels:
            vmax = max(vmax, int(matrix.get(a, {}).get(b, 0)))

    parts: list[str] = [
        f"<svg viewBox=\"0 0 {width} {height}\" xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"{esc(title)}\">",
        f"<text x=\"{left}\" y=\"24\" fill=\"var(--text)\" font-size=\"14\">{esc(title)}</text>",
        f"<text x=\"{left}\" y=\"42\" fill=\"var(--muted)\" font-size=\"12\">row=actual, col=predicted</text>",
    ]
    for i, lab in enumerate(labels):
        parts.append(
            f"<text x=\"{left + i*cell + cell/2}\" y=\"{top-8}\" text-anchor=\"middle\" "
            f"fill=\"var(--muted)\" font-size=\"11\">{esc(lab)}</text>"
        )
        parts.append(
            f"<text x=\"{left-8}\" y=\"{top + i*cell + cell/2 + 4}\" text-anchor=\"end\" "
            f"fill=\"var(--muted)\" font-size=\"11\">{esc(lab)}</text>"
        )

    for r, a in enumerate(labels):
        for c, b in enumerate(labels):
            v = int(matrix.get(a, {}).get(b, 0))
            alpha = 0.08 + 0.82 * (v / vmax)
            x = left + c * cell
            y = top + r * cell
            parts.append(f"<rect x=\"{x}\" y=\"{y}\" width=\"{cell-2}\" height=\"{cell-2}\" fill=\"rgba(37,99,235,{alpha:.3f})\" rx=\"8\"/>")
            parts.append(
                f"<text x=\"{x + cell/2}\" y=\"{y + cell/2 + 4}\" text-anchor=\"middle\" fill=\"var(--text)\" font-size=\"12\">{v}</text>"
            )

    parts.append("</svg>")
    return "".join(parts)


def svg_accuracy_bars(items: list[tuple[str, float]], *, title: str) -> str:
    if not items:
        return ""
    left = 180
    top = 24
    row_h = 30
    bar_w = 460
    width = left + bar_w + 90
    height = top + row_h * len(items) + 28

    out = [
        f"<svg viewBox=\"0 0 {width} {height}\" xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"{esc(title)}\">",
        f"<text x=\"{left}\" y=\"14\" fill=\"var(--text)\" font-size=\"13\">{esc(title)}</text>",
    ]
    for i, (name, v) in enumerate(items):
        y = top + i * row_h
        w = int(max(0.0, min(1.0, v)) * bar_w)
        color = "var(--sudoku)" if "sudoku" in name else ("var(--mqtt)" if "tls" in name else "var(--aead)")
        out.append(f"<text x=\"{left-8}\" y=\"{y+13}\" text-anchor=\"end\" fill=\"var(--muted)\" font-size=\"12\">{esc(name)}</text>")
        out.append(f"<rect x=\"{left}\" y=\"{y}\" width=\"{bar_w}\" height=\"18\" fill=\"rgba(17,24,39,.08)\" rx=\"6\"/>")
        out.append(f"<rect x=\"{left}\" y=\"{y}\" width=\"{w}\" height=\"18\" fill=\"{color}\" rx=\"6\"/>")
        out.append(f"<text x=\"{left+w+8}\" y=\"{y+13}\" fill=\"var(--muted)\" font-size=\"12\">{v*100:.1f}%</text>")
    out.append("</svg>")
    return "".join(out)


def run_evidence(out_dir: Path, *, messages: int, size: int, pad_min: int, pad_max: int, timeout_s: int = 120) -> tuple[dict[str, Any], dict[str, Any]]:
    cmd = [
        "go",
        "run",
        "./cmd/iotbci-evidence",
        "-out_dir",
        str(out_dir.relative_to(REPO_ROOT)),
        "-messages",
        str(messages),
        "-size",
        str(size),
        "-timeout",
        f"{timeout_s}s",
        "-sudoku_padding_min",
        str(pad_min),
        "-sudoku_padding_max",
        str(pad_max),
    ]
    run = run_cmd(cmd, timeout_s=timeout_s + 60)
    rep: dict[str, Any] = {}
    p = out_dir / "evidence.json"
    if p.exists():
        rep = load_json(p)
    return run, rep


def scenario_metrics(report: dict[str, Any], name: str) -> dict[str, Any]:
    for sc in report.get("scenarios") or []:
        if str(sc.get("name")) == name:
            return dict(sc.get("metrics") or {})
    return {}


def analyze_dpi_sample(data: bytes) -> dict[str, Any]:
    txt_ignore = data.decode("utf-8", errors="ignore")
    utf8_ratio = (len(txt_ignore.encode("utf-8")) / len(data)) if data else 0.0
    stripped = txt_ignore.strip()
    json_ok = False
    http_like = False
    try:
        json.loads(stripped)
        json_ok = True
    except Exception:  # noqa: BLE001
        json_ok = False
    if stripped.startswith("GET ") or stripped.startswith("POST ") or stripped.startswith("HTTP/1."):
        http_like = True
    ar = ascii_ratio(data)
    guess = "cleartext-like" if ar >= 0.85 else "encrypted-binary"
    return {
        "ascii_ratio": ar,
        "entropy": entropy_bits_per_byte(data),
        "utf8_ratio": utf8_ratio,
        "json_parse_ok": json_ok,
        "http_like": http_like,
        "dpi_guess": guess,
        "preview": txt_ignore[:96],
    }


def build_ascii_sudoku_sample(rng: random.Random, *, n: int = 1024) -> bytes:
    p = subprocess.check_output(
        ["go", "run", "./cmd/iotbci-evidence-sudoku-dump", "-key", "seed-custom", "-mode", "prefer_ascii"],
        cwd=str(REPO_ROOT),
    )
    obj = json.loads(p.decode("utf-8"))
    hint_set: set[int] = set()
    for entries in obj.get("encode_table") or []:
        for puzzle in entries:
            for b in puzzle:
                hint_set.add(int(b))
    hints = sorted(hint_set)
    pads = [int(x) for x in (obj.get("padding_pool") or [])]
    if not hints:
        hints = list(range(0x20, 0x7F))
    if not pads:
        pads = [0x20]
    out = bytearray()
    for _ in range(n):
        if rng.random() < 0.82:
            out.append(hints[rng.randrange(len(hints))] & 0xFF)
        else:
            out.append(pads[rng.randrange(len(pads))] & 0xFF)
    return bytes(out)


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20260206)

    env = {
        "generated_at": now_local_str(),
        "python": run_cmd(["python3", "--version"], timeout_s=30),
        "go": run_cmd(["go", "version"], timeout_s=30),
    }
    go_ver = ((env["go"].get("stdout") or "") + "\n" + (env["go"].get("stderr") or "")).strip()
    py_ver = ((env["python"].get("stdout") or "") + "\n" + (env["python"].get("stderr") or "")).strip()

    proto_runs_dir = out_dir / "proto_runs"
    bci_runs_dir = out_dir / "bci_runs"
    proto_runs_dir.mkdir(parents=True, exist_ok=True)
    bci_runs_dir.mkdir(parents=True, exist_ok=True)

    # 1) Protocol fingerprinting by packet-length/sequence features (aparecium-style workflow).
    proto_samples: list[LabeledSample] = []
    proto_cmds: list[dict[str, Any]] = []
    proto_repeats = 5
    for i in range(proto_repeats):
        run_dir = proto_runs_dir / f"r{i+1}"
        run_dir.mkdir(parents=True, exist_ok=True)
        cmd_ret, rep = run_evidence(run_dir, messages=800, size=256, pad_min=0, pad_max=0, timeout_s=90)
        proto_cmds.append(cmd_ret)
        for sc in rep.get("scenarios") or []:
            m = dict(sc.get("metrics") or {})
            label = str(m.get("name") or sc.get("name") or "")
            if not label:
                continue
            proto_samples.append(
                LabeledSample(
                    label=label,
                    vector=feature_from_metrics(m),
                    meta={"run": i + 1},
                )
            )

    proto_cls = nearest_centroid_loo(proto_samples)
    proto_accuracy = float(proto_cls.get("accuracy") or 0.0)

    csv_path = out_dir / "aparecium_style_protocol_features.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if proto_samples:
            dim = len(proto_samples[0].vector)
            w.writerow(["label", "run"] + [f"f{i+1}" for i in range(dim)])
            for s in proto_samples:
                w.writerow([s.label, s.meta.get("run")] + [fmt_num(float(x), 8) for x in s.vector])

    # 2) BCI side-channel attack with retransmissions (class recovery from sequence profiling).
    class_defs = [("MI-left", 80), ("MI-right", 82), ("Blink", 84), ("Rest", 86)]
    bci_repeats = 3
    bci_mode_samples: dict[str, list[LabeledSample]] = {
        "tls_baseline": [],
        "sudoku_no_padding": [],
        "sudoku_padding_20_45": [],
    }
    bci_cmds: list[dict[str, Any]] = []

    for cls_name, size in class_defs:
        for r in range(bci_repeats):
            # no padding
            run_np = bci_runs_dir / f"{cls_name}_s{size}_r{r+1}_nopad"
            run_np.mkdir(parents=True, exist_ok=True)
            cmd_np, rep_np = run_evidence(run_np, messages=180, size=size, pad_min=0, pad_max=0, timeout_s=90)
            bci_cmds.append(cmd_np)

            # padded sudoku
            run_pd = bci_runs_dir / f"{cls_name}_s{size}_r{r+1}_pad"
            run_pd.mkdir(parents=True, exist_ok=True)
            cmd_pd, rep_pd = run_evidence(run_pd, messages=180, size=size, pad_min=20, pad_max=45, timeout_s=90)
            bci_cmds.append(cmd_pd)

            m_tls = scenario_metrics(rep_np, "mqtt-3.1.1-qos0-tls")
            m_no = scenario_metrics(rep_np, "iotbci-sudoku-pure-tcp")
            m_pd = scenario_metrics(rep_pd, "iotbci-sudoku-pure-tcp")

            if m_tls:
                bci_mode_samples["tls_baseline"].append(
                    LabeledSample(label=cls_name, vector=class_feature_from_metrics(m_tls), meta={"size": size, "repeat": r + 1})
                )
            if m_no:
                bci_mode_samples["sudoku_no_padding"].append(
                    LabeledSample(label=cls_name, vector=class_feature_from_metrics(m_no), meta={"size": size, "repeat": r + 1})
                )
            if m_pd:
                bci_mode_samples["sudoku_padding_20_45"].append(
                    LabeledSample(label=cls_name, vector=class_feature_from_metrics(m_pd), meta={"size": size, "repeat": r + 1})
                )

    bci_cls = {mode: nearest_centroid_loo(samples) for mode, samples in bci_mode_samples.items()}
    bci_acc = {mode: float(v.get("accuracy") or 0.0) for mode, v in bci_cls.items()}

    # 3) DPI text-like disguise check (ASCII mode) vs TLS-like binary payload.
    ascii_sudoku_wire = build_ascii_sudoku_sample(rng, n=1024)
    tls_binary_wire = bytes(rng.getrandbits(8) for _ in range(1024))
    dpi_sudoku = analyze_dpi_sample(ascii_sudoku_wire)
    dpi_tls = analyze_dpi_sample(tls_binary_wire)

    # 4) MITM comparison: Sudoku handshake tamper rejection vs TLS MITM plaintext recovery.
    attack_path = out_dir / "attack_report.json"
    tls_mitm_path = out_dir / "tls_mitm_demo.json"
    attack_cmd = run_cmd(["go", "run", "./cmd/iotbci-attack", "-timeout", "20s", "-out", str(attack_path.relative_to(REPO_ROOT))], timeout_s=120)
    tls_mitm_cmd = run_cmd(
        ["go", "run", "./cmd/iotbci-tls-mitm-demo", "-messages", "64", "-timeout", "20s", "-out", str(tls_mitm_path.relative_to(REPO_ROOT))],
        timeout_s=120,
    )
    attack_rep = load_json(attack_path) if attack_path.exists() else {}
    tls_mitm_rep = load_json(tls_mitm_path) if tls_mitm_path.exists() else {}

    sudoku_mitm = next((x for x in (attack_rep.get("scenarios") or []) if x.get("name") == "mitm-tamper"), {})
    sudoku_mitm_block_ok = bool(sudoku_mitm.get("success"))
    tls_mitm_recover = float(tls_mitm_rep.get("recover_rate") or 0.0)
    tls_mitm_ok = bool(tls_mitm_rep.get("success"))

    summary: dict[str, Any] = {
        "generated_at": env["generated_at"],
        "env": {"go": go_ver, "python": py_ver},
        "protocol_fingerprint": {
            "repeats": proto_repeats,
            "sample_count": len(proto_samples),
            "accuracy": proto_accuracy,
            "labels": proto_cls.get("labels") or [],
            "confusion": proto_cls.get("matrix") or {},
            "features_csv": str(csv_path.relative_to(out_dir)),
            "commands": proto_cmds,
            "aparecium_reference": "https://github.com/ban6cat6/aparecium",
        },
        "bci_sidechannel": {
            "class_defs": [{"name": n, "payload_size": s} for n, s in class_defs],
            "repeats": bci_repeats,
            "accuracy_by_mode": bci_acc,
            "confusions": {mode: cls.get("matrix") for mode, cls in bci_cls.items()},
            "commands": bci_cmds,
        },
        "dpi_ascii_disguise": {
            "sudoku_ascii": dpi_sudoku,
            "tls_binary": dpi_tls,
        },
        "mitm_compare": {
            "sudoku_mitm_block_ok": sudoku_mitm_block_ok,
            "sudoku_attack_scenario": sudoku_mitm,
            "tls_mitm_recover_rate": tls_mitm_recover,
            "tls_mitm_success": tls_mitm_ok,
            "commands": {"iotbci_attack": attack_cmd, "tls_mitm_demo": tls_mitm_cmd},
        },
    }
    write_json(out_dir / "summary.json", summary)

    # HTML report
    body: list[str] = []
    body.append("<h1>06 协议指纹 + 侧写 + DPI/MITM 对照留痕</h1>")
    body.append(
        "<div class=\"card\">"
        "<h2>实验口径</h2>"
        "<ul>"
        "<li>协议指纹：基于写入长度/间隔序列样本 + 熵/ASCII/overhead 做最近质心分类（leave-one-out）。</li>"
        "<li>BCI 侧写：自拟 4 类 BCI 负载（80/82/84/86 bytes），每类多次重发采样；攻击者仅看序列特征恢复类别。</li>"
        "<li>DPI：对 ASCII-Sudoku 与 TLS-like 二进制样本做“是否明文”判定与语义解析尝试。</li>"
        "<li>MITM：对照 Sudoku（篡改失败）与 TLS（MITM 可恢复明文类别）。</li>"
        "</ul>"
        "<table>"
        f"<tr><th>Generated at</th><td><code>{esc(env['generated_at'])}</code></td></tr>"
        f"<tr><th>Go</th><td><code>{esc(go_ver)}</code></td></tr>"
        f"<tr><th>Python</th><td><code>{esc(py_ver)}</code></td></tr>"
        f"<tr><th>features CSV</th><td><code>{esc(str(csv_path.relative_to(out_dir)))}</code></td></tr>"
        "</table>"
        "</div>"
    )

    body.append(
        "<div class=\"card\">"
        "<h2>1) 协议指纹识别（长度/序列特征）</h2>"
        f"<div class=\"small\">aparecium 风格：利用可观测序列特征做协议识别；参考 <a href=\"https://github.com/ban6cat6/aparecium\" target=\"_blank\" rel=\"noopener\">ban6cat6/aparecium</a>。</div>"
        f"<div>LOO accuracy: <b>{proto_accuracy*100:.2f}%</b>（samples={len(proto_samples)}）</div>"
        + svg_confusion_matrix(proto_cls.get("matrix") or {}, proto_cls.get("labels") or [], title="Protocol confusion matrix")
        + "</div>"
    )

    acc_items = [
        ("TLS baseline", bci_acc.get("tls_baseline", 0.0)),
        ("Sudoku no padding", bci_acc.get("sudoku_no_padding", 0.0)),
        ("Sudoku padding 20-45%", bci_acc.get("sudoku_padding_20_45", 0.0)),
    ]
    body.append(
        "<div class=\"card\">"
        "<h2>2) BCI 类别侧写恢复（多次重发）</h2>"
        "<div class=\"small\">攻击者仅使用写入长度/间隔序列进行类别恢复；比较无 padding 与开启 padding 的 Sudoku。</div>"
        + svg_accuracy_bars(acc_items, title="Class recovery accuracy by mode")
        + svg_confusion_matrix(
            bci_cls["tls_baseline"].get("matrix") or {},
            bci_cls["tls_baseline"].get("labels") or [],
            title="TLS baseline confusion",
        )
        + svg_confusion_matrix(
            bci_cls["sudoku_no_padding"].get("matrix") or {},
            bci_cls["sudoku_no_padding"].get("labels") or [],
            title="Sudoku(no padding) confusion",
        )
        + svg_confusion_matrix(
            bci_cls["sudoku_padding_20_45"].get("matrix") or {},
            bci_cls["sudoku_padding_20_45"].get("labels") or [],
            title="Sudoku(padding 20-45%) confusion",
        )
        + "</div>"
    )

    body.append(
        "<div class=\"card\">"
        "<h2>3) ASCII 模式在 DPI 下的“明文伪装”</h2>"
        "<table>"
        "<tr><th>sample</th><th>ascii_ratio</th><th>entropy</th><th>utf8_ratio</th><th>json_parse_ok</th><th>http_like</th><th>dpi_guess</th></tr>"
        f"<tr><td><code>sudoku_ascii</code></td><td>{dpi_sudoku['ascii_ratio']:.4f}</td><td>{dpi_sudoku['entropy']:.4f}</td><td>{dpi_sudoku['utf8_ratio']:.4f}</td><td>{esc(dpi_sudoku['json_parse_ok'])}</td><td>{esc(dpi_sudoku['http_like'])}</td><td><b>{esc(dpi_sudoku['dpi_guess'])}</b></td></tr>"
        f"<tr><td><code>tls_binary</code></td><td>{dpi_tls['ascii_ratio']:.4f}</td><td>{dpi_tls['entropy']:.4f}</td><td>{dpi_tls['utf8_ratio']:.4f}</td><td>{esc(dpi_tls['json_parse_ok'])}</td><td>{esc(dpi_tls['http_like'])}</td><td><b>{esc(dpi_tls['dpi_guess'])}</b></td></tr>"
        "</table>"
        f"<div class=\"small\">Sudoku ASCII preview: <code>{esc(dpi_sudoku['preview'])}</code></div>"
        "</div>"
    )

    body.append(
        "<div class=\"card\">"
        "<h2>4) MITM 对照：TLS 明文恢复 vs Sudoku 拒绝篡改</h2>"
        "<table>"
        "<tr><th>scenario</th><th>result</th><th>metric</th></tr>"
        f"<tr><td><code>TLS MITM demo</code></td><td><span class=\"badge {'warn' if tls_mitm_ok else 'ok'}\">{'MITM succeeded' if tls_mitm_ok else 'MITM failed'}</span></td><td>recover_rate={tls_mitm_recover:.4f}</td></tr>"
        f"<tr><td><code>Sudoku MITM tamper</code></td><td><span class=\"badge {'ok' if sudoku_mitm_block_ok else 'warn'}\">{'tamper blocked' if sudoku_mitm_block_ok else 'tamper passed'}</span></td><td>cmd/iotbci-attack: mitm-tamper</td></tr>"
        "</table>"
        "<div class=\"small\">对照结论：在“可被信任根接管”的 TLS 链路中，MITM 可恢复明文类别；Sudoku 的握手认证链路能阻断篡改型 MITM。</div>"
        "</div>"
    )

    report_html = html_page("06 协议指纹 + 侧写 + DPI/MITM 对照", "".join(body))
    write_text(out_dir / "report.html", report_html)

    lines: list[str] = []
    lines.append(f"Generated at: {env['generated_at']}")
    lines.append(f"Protocol fingerprint LOO accuracy: {proto_accuracy*100:.2f}%")
    lines.append("BCI class recovery:")
    for name, acc in acc_items:
        lines.append(f"- {name}: {acc*100:.2f}%")
    lines.append(f"DPI guess (Sudoku ASCII): {dpi_sudoku['dpi_guess']} (ascii_ratio={dpi_sudoku['ascii_ratio']:.4f})")
    lines.append(f"DPI guess (TLS binary): {dpi_tls['dpi_guess']} (ascii_ratio={dpi_tls['ascii_ratio']:.4f})")
    lines.append(f"TLS MITM recover rate: {tls_mitm_recover:.4f}")
    lines.append(f"Sudoku MITM tamper blocked: {sudoku_mitm_block_ok}")
    lines.append("")
    write_text(out_dir / "summary.txt", "\n".join(lines))

    print(f"Wrote {out_dir / 'report.html'}")
    print(f"Wrote {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
