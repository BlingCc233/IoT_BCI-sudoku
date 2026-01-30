#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import sys

EVIDENCE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EVIDENCE_ROOT.parent
sys.path.append(str(EVIDENCE_ROOT / "_lib"))

from report import esc, html_page, now_local_str, svg_histogram, write_json, write_text  # noqa: E402


def run_cmd(cmd: list[str], *, timeout_s: int = 600) -> dict[str, object]:
    started = time.monotonic()
    try:
        p = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        dur = time.monotonic() - started
        return {
            "cmd": cmd,
            "exit_code": p.returncode,
            "duration_s": dur,
            "stdout": p.stdout,
            "stderr": p.stderr,
        }
    except Exception as e:  # noqa: BLE001
        dur = time.monotonic() - started
        return {
            "cmd": cmd,
            "exit_code": None,
            "duration_s": dur,
            "stdout": "",
            "stderr": f"failed to run: {e}",
        }


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def fmt_bytes(n: float | int) -> str:
    x = float(n)
    if x < 1024:
        return f"{x:.0f} B"
    for unit in ["KiB", "MiB", "GiB"]:
        x /= 1024.0
        if x < 1024:
            return f"{x:.2f} {unit}"
    return f"{x:.2f} TiB"


def fmt_num(x: float | int, *, digits: int = 3) -> str:
    try:
        v = float(x)
    except Exception:  # noqa: BLE001
        return str(x)
    if math.isnan(v) or math.isinf(v):
        return str(x)
    if abs(v) >= 1000:
        return f"{v:,.0f}"
    return f"{v:.{digits}f}"


def fmt_pct(x: float) -> str:
    return f"{x*100:.2f}%"


def render_code_details(*, title: str, rel_path: str, content: str, max_chars: int = 80_000) -> str:
    clipped = content
    note = ""
    if len(clipped) > max_chars:
        clipped = clipped[:max_chars]
        note = f"<div class=\"small\">(clipped to first {max_chars} chars)</div>"
    return (
        "<details class=\"card\">"
        f"<summary><b>{esc(title)}</b> — <code>{esc(rel_path)}</code></summary>"
        f"{note}"
        f"<pre>{esc(clipped)}</pre>"
        "</details>"
    )


def read_repo_text(rel_path: str) -> str:
    p = (REPO_ROOT / rel_path).resolve()
    if REPO_ROOT not in p.parents and p != REPO_ROOT:
        raise ValueError(f"path escapes repo: {rel_path}")
    return p.read_text(encoding="utf-8")


def bins_to_dict(arr: Iterable[int | float]) -> dict[int, int]:
    out: dict[int, int] = {}
    for i, v in enumerate(list(arr)):
        iv = int(v)
        if iv:
            out[i] = iv
    return out


@dataclass(frozen=True)
class MetricsRow:
    name: str
    messages: int
    payload_size: int
    overhead_ratio: float
    avg_rtt_ms: float
    p95_rtt_ms: float
    wire_entropy: float
    wire_ascii_ratio: float
    peak_heap_alloc_bytes: int
    peak_heap_inuse_bytes: int
    peak_sys_bytes: int
    wire_bps: float
    payload_bps: float
    duration_ms: float
    wire_write_calls: int
    wire_read_calls: int
    write_size_bins: list[int]
    write_iat_bins: list[int]


def to_row(m: dict[str, Any]) -> MetricsRow:
    return MetricsRow(
        name=str(m["name"]),
        messages=int(m.get("messages", 0)),
        payload_size=int(m.get("payload_size", 0)),
        overhead_ratio=float(m.get("overhead_ratio", 0.0)),
        avg_rtt_ms=float(m.get("avg_rtt_ms", 0.0)),
        p95_rtt_ms=float(m.get("p95_rtt_ms", 0.0)),
        wire_entropy=float(m.get("wire_entropy", 0.0)),
        wire_ascii_ratio=float(m.get("wire_ascii_ratio", 0.0)),
        peak_heap_alloc_bytes=int(m.get("peak_heap_alloc_bytes", 0)),
        peak_heap_inuse_bytes=int(m.get("peak_heap_inuse_bytes", 0)),
        peak_sys_bytes=int(m.get("peak_sys_bytes", 0)),
        wire_bps=float(m.get("wire_throughput_bps", 0.0)),
        payload_bps=float(m.get("payload_throughput_bps", 0.0)),
        duration_ms=float(m.get("duration_ms", 0.0)),
        wire_write_calls=int(m.get("wire_write_calls", 0)),
        wire_read_calls=int(m.get("wire_read_calls", 0)),
        write_size_bins=[int(x) for x in (m.get("wire_write_size_bins_log2") or [])],
        write_iat_bins=[int(x) for x in (m.get("wire_write_interarrival_ms_bins_log2") or [])],
    )


_SCENARIO_INFO: dict[str, dict[str, Any]] = {
    "iotbci-sudoku-pure-tcp": {
        "what": "IoTBCI + Sudoku（pure downlink，ASCII 外观优先）",
        "flow": [
            "TCP 回环：server Listen → client Dial。",
            "握手：Ed25519 证书 + X25519 临时密钥交换；握手帧可选 PSK-AEAD 保护（抗探测）。",
            "会话：AEAD record 传输；外观层：uplink=Sudoku 编码；downlink=纯 Sudoku（非 packed）。",
            "业务：client 发送固定 payload（0..255 循环字节）→ server 原样回显 → client 校验一致性。",
        ],
        "checks": [
            "握手成功且未超时（失败会直接返回 error）。",
            "echo payload 与发送 payload 完全一致（bytes.Equal）。",
            "外观：wire_ascii_ratio≈1（可打印占比很高，符合 prefer_ascii 目标）。",
        ],
        "code": [
            "internal/bench/run_iotbci_sudoku_net.go",
            "pkg/iotbci/handshake_client.go",
            "pkg/iotbci/handshake_server.go",
            "pkg/obfs/sudoku/*",
        ],
    },
    "iotbci-sudoku-packed-tcp": {
        "what": "IoTBCI + Sudoku（packed downlink，带宽优化 + 可轮转外观）",
        "flow": [
            "TCP 回环：server Listen → client Dial。",
            "握手同上；外观层：uplink=Sudoku；downlink=PackedConn（6-bit groups）。",
            "packed：把明文按 6-bit group 输出为 hint bytes，并按 padding rate 插入 padding。",
            "业务：client 发送固定 payload → server 回显 → client 校验一致性。",
        ],
        "checks": [
            "echo payload 与发送 payload 完全一致（bytes.Equal）。",
            "可轮转外观：CustomTables 会话级轮转，导致 wire_ascii_ratio 可能出现明显差异（见下方解释表）。",
        ],
        "code": [
            "internal/bench/run_iotbci_sudoku_net.go",
            "pkg/iotbci/obfs_conn.go",
            "pkg/obfs/sudoku/packed.go",
        ],
    },
    "pure-aead-tcp": {
        "what": "纯 AEAD record（无 Sudoku 外观层）",
        "flow": [
            "TCP 回环：server Listen → client Dial。",
            "双方用 PSK 派生 key/salt；在 RecordConn 上写入/读取 record。",
            "业务：client 发送固定 payload → server 回显 → client 校验一致性。",
        ],
        "checks": [
            "echo payload 与发送 payload 完全一致（bytes.Equal）。",
            "外观接近随机：wire_entropy≈8，wire_ascii_ratio≈95/256（随机字节落在可打印区间的期望）。",
        ],
        "code": ["internal/bench/run_pure_aead_net.go", "pkg/iotbci/recordconn.go"],
    },
    "dtls-ecdhe-ecdsa-aes128gcm": {
        "what": "DTLS 基线（UDP + 证书/ECDHE + AES-128-GCM）",
        "flow": [
            "UDP 回环：server ListenPacket → client DialUDP。",
            "DTLS 握手：自签 CA 签发的证书 + ECDHE key exchange + AES-128-GCM。",
            "业务：client 写 payload → server 读满后回显 → client 读满并校验一致性。",
        ],
        "checks": [
            "DTLS 握手成功（pion/dtls 返回 conn）。",
            "echo payload 与发送 payload 完全一致（bytes.Equal）。",
            "证明 UDP 信息链路闭环：udp_ports 非空（由 ready callback 回填）。",
        ],
        "code": ["internal/bench/run_dtls_cert.go"],
    },
    "coap-udp": {
        "what": "CoAP 基线（UDP CON/ACK，POST /bci）",
        "flow": [
            "UDP 回环：server ListenPacket → client DialUDP。",
            "client 发送 CON POST /bci（含 token/msgID/payload）。",
            "server 校验报文头/路径，回 ACK Content，并回显原 payload。",
            "client 解析 response，并逐字节比对回显 payload。",
        ],
        "checks": [
            "request/response 字段符合预期（version/type/code/path/token/msgID）。",
            "echo payload 长度与内容一致（逐字节比对）。",
        ],
        "code": ["internal/bench/run_coap.go"],
    },
    "mqtt-3.1.1-qos0-tls": {
        "what": "MQTT 基线（TCP + TLS(证书/ECDHE) + QoS0，内置 broker）",
        "flow": [
            "TCP 回环：启动内置 broker（TLS server）。",
            "TLS 握手：自签 CA 签发的证书 + TLS 1.3(ECDHE) 建立加密通道。",
            "server client：订阅 bci/req，收到后 publish 到 bci/resp。",
            "device client：publish 到 bci/req，订阅 bci/resp 并等待回显。",
            "双方逐字节比对回显 payload。",
        ],
        "checks": [
            "topic 流程正确（req/resp 主题匹配）。",
            "echo payload 长度与内容一致（逐字节比对）。",
        ],
        "code": ["internal/bench/run_mqtt.go"],
    },
}


def metric_table(rows: list[MetricsRow], *, title: str) -> str:
    header = (
        "<tr>"
        "<th>scenario</th>"
        "<th>overhead_ratio</th>"
        "<th>avg_rtt_ms</th>"
        "<th>p95_rtt_ms</th>"
        "<th>wire_entropy</th>"
        "<th>wire_ascii_ratio</th>"
        "<th>peak_heap_alloc</th>"
        "<th>peak_heap_inuse</th>"
        "<th>peak_sys</th>"
        "<th>wire_bps</th>"
        "<th>payload_bps</th>"
        "</tr>"
    )
    trs: list[str] = []
    for r in rows:
        trs.append(
            "<tr>"
            f"<td><code>{esc(r.name)}</code></td>"
            f"<td>{fmt_num(r.overhead_ratio, digits=3)}</td>"
            f"<td>{fmt_num(r.avg_rtt_ms, digits=3)}</td>"
            f"<td>{fmt_num(r.p95_rtt_ms, digits=3)}</td>"
            f"<td>{fmt_num(r.wire_entropy, digits=3)}</td>"
            f"<td>{fmt_pct(r.wire_ascii_ratio)}</td>"
            f"<td>{esc(fmt_bytes(r.peak_heap_alloc_bytes))}</td>"
            f"<td>{esc(fmt_bytes(r.peak_heap_inuse_bytes))}</td>"
            f"<td>{esc(fmt_bytes(r.peak_sys_bytes))}</td>"
            f"<td>{esc(fmt_bytes(r.wire_bps))}/s</td>"
            f"<td>{esc(fmt_bytes(r.payload_bps))}/s</td>"
            "</tr>"
        )
    return (
        "<div class=\"card\">"
        f"<h2>{esc(title)}</h2>"
        "<table>"
        + header
        + "".join(trs)
        + "</table>"
        "</div>"
    )


def svg_bar_compare(rows: list[MetricsRow], *, title: str, value_fn, fmt_fn) -> str:
    # Simple horizontal bar chart.
    if not rows:
        return ""
    values = [float(value_fn(r)) for r in rows]
    vmax = max(values) or 1.0

    left = 180
    top = 22
    row_h = 26
    bar_w = 520
    height = top + row_h * len(rows) + 26
    width = left + bar_w + 70

    bars: list[str] = []
    labels: list[str] = []
    for i, r in enumerate(rows):
        v = float(value_fn(r))
        w = int(bar_w * (v / vmax))
        y = top + i * row_h
        bars.append(
            f"<rect x=\"{left}\" y=\"{y}\" width=\"{w}\" height=\"18\" fill=\"#60a5fa\" rx=\"4\" />"
        )
        labels.append(
            f"<text x=\"{left-8}\" y=\"{y+14}\" text-anchor=\"end\" fill=\"#e5e7eb\" font-size=\"12\">{esc(r.name)}</text>"
        )
        labels.append(
            f"<text x=\"{left + w + 6}\" y=\"{y+14}\" fill=\"#9ca3af\" font-size=\"12\">{esc(fmt_fn(v))}</text>"
        )

    axes = (
        f"<text x=\"{left}\" y=\"14\" fill=\"#e5e7eb\" font-size=\"13\">{esc(title)}</text>"
        f"<line x1=\"{left}\" y1=\"{top-6}\" x2=\"{left}\" y2=\"{height-20}\" stroke=\"rgba(255,255,255,.18)\" />"
    )
    return (
        f"<svg viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"{esc(title)}\" "
        "xmlns=\"http://www.w3.org/2000/svg\">"
        + axes
        + "".join(bars)
        + "".join(labels)
        + "</svg>"
    )


def sudoku_pattern_analysis() -> dict[str, Any]:
    patterns = ["xppppxvv", "vppxppvx"]
    out: dict[str, Any] = {"patterns": []}

    for pat in patterns:
        dump = subprocess.check_output(
            ["go", "run", "./cmd/iotbci-evidence-sudoku-dump", "-key", "seed-custom", "-mode", "prefer_entropy", "-pattern", pat],
            cwd=str(REPO_ROOT),
        )
        obj = json.loads(dump.decode("utf-8"))

        hint_set: set[int] = set()
        for entries in obj["encode_table"]:
            for puzzle in entries:
                for b in puzzle:
                    hint_set.add(int(b))
        hint_ascii = sum(1 for b in hint_set if 0x20 <= b <= 0x7E)

        pad_pool = [int(x) for x in obj.get("padding_pool") or []]
        pad_ascii = sum(1 for b in pad_pool if 0x20 <= b <= 0x7E)

        out["patterns"].append(
            {
                "pattern": pat,
                "hint_unique": len(hint_set),
                "hint_ascii_ratio": (hint_ascii / max(1, len(hint_set))),
                "padding_pool_len": len(pad_pool),
                "padding_ascii_ratio": (pad_ascii / max(1, len(pad_pool))),
                "padding_pool_min": min(pad_pool) if pad_pool else None,
                "padding_pool_max": max(pad_pool) if pad_pool else None,
                "note": (
                    "hint ASCII 比例决定 packed 模式主要字节是否落在 0x20..0x7e；"
                    "这会直接影响 bench/evidence 的 wire_ascii_ratio（如果本次会话选中了该 pattern）。"
                ),
            }
        )
    return out


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    env = {
        "generated_at": now_local_str(),
        "python": run_cmd(["python3", "--version"], timeout_s=30),
        "go": run_cmd(["go", "version"], timeout_s=30),
    }
    go_ver = ((env["go"].get("stdout") or "") + "\n" + (env["go"].get("stderr") or "")).strip()
    py_ver = ((env["python"].get("stdout") or "") + "\n" + (env["python"].get("stderr") or "")).strip()

    # 1) Run reproducible benchmarks.
    bench_path = out_dir / "bench.json"
    evidence_dir = out_dir / "evidence_out"
    evidence_json = evidence_dir / "evidence.json"

    bench_cmd = [
        "go",
        "run",
        "./cmd/iotbci-bench",
        "-messages",
        "200",
        "-size",
        "256",
        "-timeout",
        "30s",
        "-out",
        str(bench_path.relative_to(REPO_ROOT)),
    ]
    evidence_cmd = [
        "go",
        "run",
        "./cmd/iotbci-evidence",
        "-out_dir",
        str(evidence_dir.relative_to(REPO_ROOT)),
        "-messages",
        "200",
        "-size",
        "256",
        "-timeout",
        "30s",
    ]

    cmd_runs = {
        "iotbci-bench": run_cmd(bench_cmd, timeout_s=600),
        "iotbci-evidence": run_cmd(evidence_cmd, timeout_s=900),
    }

    # 2) Load results (even if command failed, try to read any existing output).
    bench_report: dict[str, Any] | None = None
    if bench_path.exists():
        bench_report = load_json(bench_path)
    evidence_report: dict[str, Any] | None = None
    if evidence_json.exists():
        evidence_report = load_json(evidence_json)

    bench_rows: list[MetricsRow] = []
    if bench_report and isinstance(bench_report.get("results"), list):
        bench_rows = [to_row(m) for m in bench_report["results"]]

    evidence_rows: list[MetricsRow] = []
    if evidence_report and isinstance(evidence_report.get("scenarios"), list):
        evidence_rows = [to_row(sc["metrics"]) for sc in evidence_report["scenarios"]]
    evidence_scenarios: list[dict[str, Any]] = []
    if evidence_report and isinstance(evidence_report.get("scenarios"), list):
        for sc in evidence_report["scenarios"]:
            evidence_scenarios.append(
                {
                    "name": sc.get("name"),
                    "tcp_ports": sc.get("tcp_ports") or [],
                    "udp_ports": sc.get("udp_ports") or [],
                    "metrics": sc.get("metrics") or {},
                }
            )

    # 3) Sudoku custom-table effect analysis (解释 packed ascii_ratio 波动来源).
    pattern_info = sudoku_pattern_analysis()

    summary_obj: dict[str, Any] = {
        "generated_at": env["generated_at"],
        "commands": cmd_runs,
        "bench_json": str(bench_path.relative_to(REPO_ROOT)),
        "evidence_json": str(evidence_json.relative_to(REPO_ROOT)) if evidence_json.exists() else str(evidence_json),
        "bench_rows": [r.__dict__ for r in bench_rows],
        "evidence_rows": [r.__dict__ for r in evidence_rows],
        "sudoku_pattern_analysis": pattern_info,
    }
    write_json(out_dir / "summary.json", summary_obj)

    # 4) Render HTML report.
    body: list[str] = []
    body.append("<h1>05 基线对比实验留痕（DTLS/CoAP/MQTT/pure-AEAD vs IoTBCI-Sudoku）</h1>")

    body.append(
        "<div class=\"card\">"
        "<h2>目标（对齐进度计划表）</h2>"
        "<ul>"
        "<li>说明对比了什么：统一 payload（默认 256B）与消息轮次（默认 200 RTT），输出 overhead/latency/吞吐/内存/外观指标。</li>"
        "<li>说明如何对比：给出每个协议的运行流程、验证点（为什么能证明成功），并保留一键复现命令与原始 JSON。</li>"
        "<li>说明结论：给出 Sudoku（pure/packed）的优势与代价（好在哪/坏在哪），并解释 packed 外观指标为何会波动。</li>"
        "</ul>"
        "<table>"
        f"<tr><th>Generated at</th><td><code>{esc(env['generated_at'])}</code></td></tr>"
        f"<tr><th>Go</th><td><code>{esc(go_ver)}</code></td></tr>"
        f"<tr><th>Python</th><td><code>{esc(py_ver)}</code></td></tr>"
        f"<tr><th>bench.json</th><td><code>{esc(str(bench_path.relative_to(out_dir)))}</code></td></tr>"
        f"<tr><th>evidence.json</th><td><code>{esc(str(evidence_json.relative_to(out_dir)))}</code></td></tr>"
        "</table>"
        "</div>"
    )

    body.append(
        "<div class=\"card\">"
        "<h2>对比口径（指标定义）</h2>"
        "<ul>"
        "<li><code>overhead_ratio</code> = wire_bytes_total / payload_bytes_total（越小越省带宽）。</li>"
        "<li><code>avg_rtt_ms</code>/<code>p95_rtt_ms</code>：一次“发送+回显”的 steady-state 处理时延（越小越快，不包含握手/建连/订阅等初始化）。</li>"
        "<li><code>wire_entropy</code> 与 <code>wire_ascii_ratio</code>：对线上 payload 字节计算（外观侧写：随机性/可打印比例）。</li>"
        "<li><code>wire_write_size_bins_log2</code>/<code>wire_write_interarrival_ms_bins_log2</code>：写尺寸/写间隔直方图（外观侧写：包长/时序）。</li>"
        "<li><code>peak_heap_*</code>/<code>peak_sys</code>：Go runtime 采样近似峰值内存（论文需注明采样方法与误差来源）。</li>"
        "</ul>"
        "<div class=\"small\">详细字段解释见：<code>doc/BENCHMARKS.md</code></div>"
        "</div>"
    )

    if evidence_rows:
        body.append(metric_table(evidence_rows, title="结果（推荐）：cmd/iotbci-evidence 回环真实 socket"))
        body.append(
            "<div class=\"card\">"
            "<h2>核心对比图（evidence）</h2>"
            + svg_bar_compare(
                evidence_rows,
                title="overhead_ratio（越小越好）",
                value_fn=lambda r: r.overhead_ratio,
                fmt_fn=lambda v: f"{v:.3f}",
            )
            + svg_bar_compare(
                evidence_rows,
                title="avg_rtt_ms（越小越好）",
                value_fn=lambda r: r.avg_rtt_ms,
                fmt_fn=lambda v: f"{v:.3f} ms",
            )
            + svg_bar_compare(
                evidence_rows,
                title="peak_heap_inuse（越小越省内存）",
                value_fn=lambda r: r.peak_heap_inuse_bytes,
                fmt_fn=lambda v: fmt_bytes(v),
            )
            + svg_bar_compare(
                evidence_rows,
                title="wire_entropy（越大越随机）",
                value_fn=lambda r: r.wire_entropy,
                fmt_fn=lambda v: f"{v:.3f}",
            )
            + svg_bar_compare(
                evidence_rows,
                title="wire_ascii_ratio（0x20..0x7e 占比）",
                value_fn=lambda r: r.wire_ascii_ratio,
                fmt_fn=lambda v: f"{v*100:.2f}%",
            )
            + "</div>"
        )

        body.append(
            "<div class=\"card\">"
            "<h2>内存开销分析（为什么这些数可信）</h2>"
            "<ul>"
            "<li>采样方法：bench 内部以固定周期采样 <code>runtime.MemStats</code>，并取近似峰值（见 <code>internal/bench/mem_sampler.go</code>）。</li>"
            "<li><code>peak_heap_inuse</code>：堆上正在使用的对象总量（越小越适合小内存设备）。</li>"
            "<li><code>peak_heap_alloc</code>：累计分配的近似峰值快照（用于定位“是否频繁分配/回收”导致 GC 抖动）。</li>"
            "<li><code>peak_sys</code>：Go runtime 向 OS 申请的总内存（包含堆、栈、运行时元数据等）。</li>"
            "</ul>"
            "<div class=\"small\">注意：这是“采样近似值”，不是 pprof 精确剖析；用于月报/对比趋势足够，论文写作需注明误差来源。</div>"
            "</div>"
        )

        # Per-scenario appearance histograms.
        rows_sorted = sorted(evidence_rows, key=lambda r: r.name)
        for r in rows_sorted:
            body.append(
                "<div class=\"card\">"
                f"<h2>外观直方图：<code>{esc(r.name)}</code></h2>"
                "<div class=\"grid\">"
                + svg_histogram(bins_to_dict(r.write_size_bins), title="wire_write_size_bins_log2（写入尺寸 log2 bins）")
                + svg_histogram(bins_to_dict(r.write_iat_bins), title="wire_write_interarrival_ms_bins_log2（写入间隔 ms log2 bins）")
                + "</div>"
                "<div class=\"small\">提示：这些 bins 来自 bench 的 CountingConn/CountingPacketConn 记录写调用；用于论文的“包长/时序特征”侧写。</div>"
                "</div>"
            )

        body.append(
            "<div class=\"card\">"
            "<h2>逐协议过程说明（如何运行起来 & 为什么能证明成功）</h2>"
            "<div class=\"small\">该部分是“可复制到月报/论文”的过程证据链摘要；更底层细节可展开后面的源码。</div>"
            "</div>"
        )
        for sc in evidence_scenarios:
            name = str(sc.get("name") or "")
            info = _SCENARIO_INFO.get(name) or {}
            tcp_ports = sc.get("tcp_ports") or []
            udp_ports = sc.get("udp_ports") or []
            transport = "TCP" if tcp_ports else ("UDP" if udp_ports else "unknown")

            metrics = dict(sc.get("metrics") or {})
            metrics.setdefault("name", name)
            m = to_row(metrics)

            flow = info.get("flow") or []
            checks = info.get("checks") or []
            code = info.get("code") or []

            flow_html = (
                "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in flow) + "</ul>"
                if flow
                else "<div class=\"small\">(no flow description)</div>"
            )
            checks_html = (
                "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in checks) + "</ul>"
                if checks
                else "<div class=\"small\">(no checks description)</div>"
            )
            code_html = (
                "<ul>" + "".join(f"<li><code>{esc(x)}</code></li>" for x in code) + "</ul>"
                if code
                else "<div class=\"small\">(no code refs)</div>"
            )

            body.append(
                "<div class=\"card\">"
                f"<h2><code>{esc(name)}</code> — {esc(info.get('what') or '')}</h2>"
                "<table>"
                f"<tr><th>transport</th><td><code>{esc(transport)}</code></td></tr>"
                f"<tr><th>tcp_ports</th><td><code>{esc(tcp_ports)}</code></td></tr>"
                f"<tr><th>udp_ports</th><td><code>{esc(udp_ports)}</code></td></tr>"
                f"<tr><th>messages</th><td>{esc(m.messages)}</td></tr>"
                f"<tr><th>payload_size</th><td>{esc(m.payload_size)} B</td></tr>"
                f"<tr><th>overhead_ratio</th><td>{fmt_num(m.overhead_ratio)}</td></tr>"
                f"<tr><th>avg/p95_rtt</th><td>{fmt_num(m.avg_rtt_ms)} ms / {fmt_num(m.p95_rtt_ms)} ms</td></tr>"
                f"<tr><th>wire_entropy</th><td>{fmt_num(m.wire_entropy)}</td></tr>"
                f"<tr><th>wire_ascii_ratio</th><td>{fmt_pct(m.wire_ascii_ratio)}</td></tr>"
                "</table>"
                "<h3>流程</h3>"
                f"{flow_html}"
                "<h3>验证点</h3>"
                f"{checks_html}"
                "<h3>相关实现（仓库内路径）</h3>"
                f"{code_html}"
                "</div>"
            )

    if bench_rows:
        body.append(metric_table(bench_rows, title="补充：cmd/iotbci-bench（部分场景用 net.Pipe 隔离 OS 噪声）"))

    # Explain Sudoku packed ASCII discrepancy via custom-table analysis.
    pat_lines: list[str] = []
    for p in pattern_info.get("patterns", []):
        pat_lines.append(
            "<tr>"
            f"<td><code>{esc(p['pattern'])}</code></td>"
            f"<td>{esc(p['hint_unique'])}</td>"
            f"<td>{fmt_pct(float(p['hint_ascii_ratio']))}</td>"
            f"<td>{esc(p['padding_pool_len'])}</td>"
            f"<td>{fmt_pct(float(p['padding_ascii_ratio']))}</td>"
            "</tr>"
        )
    body.append(
        "<div class=\"card\">"
        "<h2>解释：为什么 packed 模式的 wire_ascii_ratio 可能波动很大？</h2>"
        "<div class=\"small\">原因：packed 模式启用了 <code>CustomTables</code>（会话级轮转），当前配置包含两个 pattern；不同 pattern 的 hint 字节集合是否落在可打印 ASCII（0x20..0x7e）差异很大。</div>"
        "<table>"
        "<tr><th>pattern</th><th>unique hint bytes</th><th>hint ASCII ratio</th><th>padding pool</th><th>padding ASCII ratio</th></tr>"
        + "".join(pat_lines)
        + "</table>"
        "<div class=\"small\">结论：如果会话选中了 <code>vppxppvx</code>，hint 本身约 36% 可打印，因此整体 wire_ascii_ratio 可能接近 0.36；如果选中 <code>xppppxvv</code>，hint 全部不可打印，则整体 wire_ascii_ratio 会主要由 padding 决定（通常很低）。</div>"
        "</div>"
    )

    body.append(
        "<div class=\"card\">"
        "<h2>Sudoku 好在哪 / 坏在哪（基于以上指标的可复现实证）</h2>"
        "<h3>好（优势）</h3>"
        "<ul>"
        "<li><b>可控外观</b>：pure 模式几乎全可打印（wire_ascii_ratio≈1），packed+custom table 可在“低 ASCII / 中 ASCII”之间切换（见上表）。</li>"
        "<li><b>侧写维度更丰富</b>：通过 padding rate、write call 切分、packed 6-bit group，可调节长度分布与写间隔分布（见直方图）。</li>"
        "<li><b>与安全层解耦</b>：外观层在 AEAD 之外工作；pure-aead/DTLS 即使加密强，外观仍接近随机（ASCII≈95/256）。</li>"
        "</ul>"
        "<h3>坏（代价/风险）</h3>"
        "<ul>"
        "<li><b>带宽开销高</b>：Sudoku（pure/packed）overhead_ratio 明显高于 pure-aead/DTLS/CoAP（见表）。</li>"
        "<li><b>实现复杂度与可解释性成本</b>：需要维护 table、probe、padding、packed framing 等；论文必须把口径/参数写清楚。</li>"
        "<li><b>外观可被“识别为人为设计”</b>：例如 pure 模式 ASCII 过高、packed 的 hintMask 结构等；需要用多表轮转与统计评估来支撑“更像某类自然流量”。</li>"
        "</ul>"
        "</div>"
    )

    # Process / algorithm evidence: point to code used for baselines.
    body.append(
        "<div class=\"card\">"
        "<h2>“为什么能证明成功？”（验证点/过程证据链）</h2>"
        "<ul>"
        "<li>所有场景都以“client 发送固定 payload → server 回显 → client 接收”作为闭环；若读写失败或超时，会返回 error 并在 JSON 里缺失。</li>"
        "<li>CoAP/MQTT 场景在实现中逐字节比对 echo payload（强验证）；其余场景在本仓库中也加入回显一致性校验（见对应实现文件）。</li>"
        "<li>DTLS/CoAP 属于 UDP；MQTT/pure-aead/sudoku 属于 TCP（见 <code>cmd/iotbci-evidence</code> 输出中的 tcp_ports/udp_ports）。</li>"
        "</ul>"
        "</div>"
    )

    # Embed key source files for screenshot/copy.
    body.append(render_code_details(title="bench orchestrator", rel_path="internal/bench/run_all.go", content=read_repo_text("internal/bench/run_all.go")))
    body.append(
        render_code_details(
            title="DTLS baseline (cert/ECDHE AES-128-GCM)",
            rel_path="internal/bench/run_dtls_cert.go",
            content=read_repo_text("internal/bench/run_dtls_cert.go"),
        )
    )
    body.append(render_code_details(title="CoAP baseline (UDP CON/ACK)", rel_path="internal/bench/run_coap.go", content=read_repo_text("internal/bench/run_coap.go")))
    body.append(
        render_code_details(
            title="MQTT baseline (in-process broker, QoS0, TLS)",
            rel_path="internal/bench/run_mqtt.go",
            content=read_repo_text("internal/bench/run_mqtt.go"),
        )
    )
    body.append(render_code_details(title="TLS/DTLS local cert helper", rel_path="internal/bench/tlsutil.go", content=read_repo_text("internal/bench/tlsutil.go")))
    body.append(render_code_details(title="Pure AEAD baseline (RecordConn)", rel_path="internal/bench/run_pure_aead.go", content=read_repo_text("internal/bench/run_pure_aead.go")))
    body.append(render_code_details(title="IoTBCI-Sudoku (micro)", rel_path="internal/bench/run_iotbci_sudoku.go", content=read_repo_text("internal/bench/run_iotbci_sudoku.go")))
    body.append(render_code_details(title="IoTBCI-Sudoku (loopback TCP)", rel_path="internal/bench/run_iotbci_sudoku_net.go", content=read_repo_text("internal/bench/run_iotbci_sudoku_net.go")))
    body.append(render_code_details(title="Sudoku obfs fast RNG (non-crypto)", rel_path="pkg/obfs/sudoku/fast_rng.go", content=read_repo_text("pkg/obfs/sudoku/fast_rng.go")))
    body.append(render_code_details(title="Sudoku obfs Conn (pure)", rel_path="pkg/obfs/sudoku/conn.go", content=read_repo_text("pkg/obfs/sudoku/conn.go")))
    body.append(render_code_details(title="Sudoku obfs PackedConn (6-bit)", rel_path="pkg/obfs/sudoku/packed.go", content=read_repo_text("pkg/obfs/sudoku/packed.go")))
    body.append(render_code_details(title="Evidence harness (loopback runner)", rel_path="cmd/iotbci-evidence/main.go", content=read_repo_text("cmd/iotbci-evidence/main.go")))
    body.append(render_code_details(title="Benchmark field definitions", rel_path="internal/bench/report.go", content=read_repo_text("internal/bench/report.go")))
    body.append(render_code_details(title="Benchmark methodology doc", rel_path="doc/BENCHMARKS.md", content=read_repo_text("doc/BENCHMARKS.md")))

    report_html = html_page("05 基线对比实验留痕", "".join(body))
    write_text(out_dir / "report.html", report_html)

    # Copy-friendly text summary for monthly report.
    lines: list[str] = []
    lines.append(f"Generated at: {env['generated_at']}")
    lines.append(f"Go: {go_ver}")
    lines.append("Outputs:")
    lines.append(f"- out/bench.json")
    lines.append(f"- out/evidence_out/evidence.json")
    lines.append("")
    lines.append("Key notes:")
    lines.append("- 推荐用 cmd/iotbci-evidence 的 loopback 结果写论文对比；micro-bench 仅作补充。")
    lines.append("- packed 模式外观指标（wire_ascii_ratio）会随 CustomTables 会话轮转波动：xppppxvv 的 hint 全不可打印；vppxppvx 的 hint 约 36% 可打印。")
    lines.append("- Sudoku 的优势是“可控外观+可调侧写特征”，代价是较高的带宽开销与实现复杂度。")
    lines.append("")
    write_text(out_dir / "summary.txt", "\n".join(lines) + "\n")

    print(f"Wrote {out_dir / 'report.html'}")
    print(f"Wrote {out_dir / 'summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
