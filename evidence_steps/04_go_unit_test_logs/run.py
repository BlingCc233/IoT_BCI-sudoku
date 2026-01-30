#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

import sys

EVIDENCE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EVIDENCE_ROOT.parent
sys.path.append(str(EVIDENCE_ROOT / "_lib"))

from report import esc, hexdump, html_page, now_local_str, write_json, write_text  # noqa: E402


def run_cmd(cmd: list[str], *, timeout_s: int = 300) -> dict[str, object]:
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


def parse_go_test_names(output: str) -> list[str]:
    tests: list[str] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if line.startswith("=== RUN"):
            parts = line.split()
            if parts:
                tests.append(parts[-1])
    return tests


def read_rel(path: str) -> str:
    p = (REPO_ROOT / path).resolve()
    # Prevent path escape.
    if REPO_ROOT not in p.parents and p != REPO_ROOT:
        raise ValueError(f"path escapes repo: {path}")
    return p.read_text(encoding="utf-8")


def render_code_details(*, title: str, rel_path: str, content: str, max_chars: int = 120_000) -> str:
    clipped = content
    clipped_note = ""
    if len(clipped) > max_chars:
        clipped = clipped[:max_chars]
        clipped_note = f"<div class=\"small\">(clipped to first {max_chars} chars)</div>"
    return (
        "<details class=\"card\">"
        f"<summary><b>{esc(title)}</b> — <code>{esc(rel_path)}</code></summary>"
        f"{clipped_note}"
        f"<pre>{esc(clipped)}</pre>"
        "</details>"
    )


def demo_frame_bytes() -> dict[str, object]:
    payload = b"bci-frame"
    header = len(payload).to_bytes(4, "big")
    wire = header + payload
    return {
        "payload": payload.decode("utf-8", errors="replace"),
        "header_hex": header.hex(),
        "wire_hex": wire.hex(),
        "hexdump": hexdump(wire),
        "explain": "Frame format: [len: u32 big-endian] + payload bytes",
    }


def demo_uot_bytes() -> dict[str, object]:
    # Mirror pkg/iotbci/uot framing:
    # preface: 0xEE 0x01, then header: addrLen(u16be) + payloadLen(u16be),
    # then addr bytes + payload bytes.
    magic = bytes([0xEE, 0x01])
    addr = "127.0.0.1:9000"
    payload = b"udp-payload-demo"
    addr_b = addr.encode("utf-8")
    header = len(addr_b).to_bytes(2, "big") + len(payload).to_bytes(2, "big")
    wire = magic + header + addr_b + payload
    return {
        "addr": addr,
        "payload": payload.decode("utf-8", errors="replace"),
        "wire_len": len(wire),
        "wire_hexdump": hexdump(wire),
        "parsed": {
            "magic": "0xEE",
            "version": "0x01",
            "addrLen": len(addr_b),
            "payloadLen": len(payload),
        },
        "explain": "UoT framing: [preface 0xEE 0x01] + [addrLen u16be][payloadLen u16be] + addr + payload",
    }


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    go_ver = run_cmd(["go", "version"], timeout_s=60)

    checks = [
        {
            "id": "sudoku",
            "name": "Sudoku custom layout tests (obfs layer)",
            "relates_to": "外观层编解码正确性测试 / 自定义 x/v/p",
            "cmd": ["go", "test", "./pkg/obfs/sudoku", "-run", "TestCustomLayout", "-count=1", "-v"],
            "claims": [
                "自定义 x/v/p pattern 能正确解析，并生成可识别的 hint 字节（isHint）。",
                "padding pool 通过“丢 1 个 x 位”构造，保证 padding 永远不会被误判为 hint（避免解码误收集）。",
                "Conn 与 PackedConn 的 round-trip 在 net.Pipe 下可通过（证明编解码链路闭环）。",
            ],
            "algorithm": [
                "custom layout：2 个 x 位恒为 1 形成 hintMask；p(4 bits) 表示 cell position(0..15)，v(2 bits) 表示 cell value(0..3)。",
                "decoder：只收集 isHint==true 的字节；每 4 个 hint 组成无序集合，排序后查 DecodeMap 还原 1 byte；map miss 返回 ErrInvalidSudokuMapMiss。",
                "padding：从候选字节中“丢掉 1 个 x 位”，并要求 popcount>=5，使 padding 既不被识别为 hint，又更难出现明显静态特征。",
            ],
            "evidence_links": [
                "evidence_steps/01_sudoku_codec_validation/out/report.html (byte->4x4 全量映射+编解码过程追踪)",
                "evidence_steps/02_padding_custom_layout/out/report.html (hint/padding 字节空间分布+统计)",
                "evidence_steps/03_hamming1_analysis/out/report.html (汉明距离边界分析)",
            ],
            "code_refs": {
                "impl": ["pkg/obfs/sudoku/layout.go", "pkg/obfs/sudoku/table.go", "pkg/obfs/sudoku/conn.go"],
                "tests": ["pkg/obfs/sudoku/custom_layout_test.go"],
                "docs": ["doc/OBFS_SUDOKU.md"],
            },
        },
        {
            "id": "handshake",
            "name": "Handshake unit tests (Ed25519/X25519/anti-replay)",
            "relates_to": "握手流程单元测试日志 / 抗重放",
            "cmd": ["go", "test", "./pkg/iotbci", "-run", "TestHandshake", "-count=1", "-v"],
            "claims": [
                "握手完成后双方获得可用的安全连接（能在 net.Pipe 上读写应用数据）。",
                "服务端能从握手元信息中识别对端身份（PeerSubject）。",
                "重放检测可拒绝“相同随机数/nonce 的第二次握手”（ErrReplayDetected）。",
            ],
            "algorithm": [
                "身份：证书由 master key 签发；握手期验证证书与身份字段。",
                "密钥：握手阶段生成随机数/nonce 与临时密钥交换材料，派生握手与会话 AEAD key。",
                "抗重放：ReplayCache 对 token 做 sha256 后在窗口内判重；容量满用 ring eviction 保持小内存可控。",
            ],
            "evidence_links": ["doc/HANDSHAKE.md", "pkg/iotbci/replay.go"],
            "code_refs": {
                "impl": ["pkg/iotbci/replay.go"],
                "tests": ["pkg/iotbci/handshake_test.go"],
                "docs": ["doc/HANDSHAKE.md"],
            },
        },
        {
            "id": "frame",
            "name": "TCP stream framing (frame) tests",
            "relates_to": "基础帧化（TCP流分帧）正确性",
            "cmd": ["go", "test", "./pkg/iotbci/frame", "-count=1", "-v"],
            "claims": [
                "frame.Write 写入 [u32len + payload]；frame.Read 能按 declared length 正确读回 payload。",
                "Read 会拒绝超出 maxSize 的 declared length，避免内存/资源滥用。",
            ],
            "algorithm": [
                "帧格式：4 字节大端长度前缀（uint32）+ payload。",
                "读取：先 io.ReadFull 读 header，再按 maxSize 约束申请缓冲并 io.ReadFull 读 payload。",
            ],
            "demo": {"frame_example": demo_frame_bytes()},
            "code_refs": {
                "impl": ["pkg/iotbci/frame/frame.go"],
                "tests": ["pkg/iotbci/frame/frame_test.go"],
                "docs": [],
            },
        },
        {
            "id": "uot",
            "name": "UoT (UDP over TCP) tests",
            "relates_to": "UoT 封装模块单测",
            "cmd": ["go", "test", "./pkg/iotbci/uot", "-count=1", "-v"],
            "claims": [
                "该模块实现“UDP over TCP”的语义：在 stream conn 上保留 datagram 边界并支持 ReadFrom/WriteTo。",
                "preface(magic+version) 能将 UoT 会话从普通 TCP 流中区分出来（证明“确实是 UoT”）。",
                "payload 与 addr 能被编码、传输、解码回原值（证明“UDP 信息传成功了”）。",
                "ShortBuffer 场景会丢弃剩余字节以保持 framing 对齐，并返回 io.ErrShortBuffer。",
            ],
            "algorithm": [
                "preface：2 bytes = [MagicByte=0xEE][version=0x01]（WritePreface/ReadPreface）。",
                "datagram frame：4 bytes header = [addrLen u16be][payloadLen u16be]，随后 addr bytes + payload bytes（WriteDatagram/ReadDatagram）。",
                "PacketConn：ReadFrom/WriteTo 基于上述 frame；并用 readMu/writeMu 保证并发下 framing 不交织。",
            ],
            "demo": {"uot_example": demo_uot_bytes()},
            "code_refs": {
                "impl": ["pkg/iotbci/uot/uot.go"],
                "tests": ["pkg/iotbci/uot/uot_test.go"],
                "docs": [],
            },
        },
        {
            "id": "fallback",
            "name": "Fallback / suspicious handling tests (node)",
            "relates_to": "回落策略触发测试 / 异常输入处理",
            "cmd": ["go", "test", "./internal/node", "-run", "TestHandleSuspicious", "-count=1", "-v"],
            "claims": [
                "当识别到可疑流量时，系统会把“已记录/缓冲的坏数据 + 后续 live bytes”转发到 fallback 服务，并把响应再转回客户端。",
                "silent 动作会丢弃输入并尽快返回（避免资源占用）。",
            ],
            "algorithm": [
                "HandleSuspicious：若 action=silent 则 io.Copy(io.Discard) + hold + close；否则 dial fallback TCP。",
                "若 conn 提供 GetBufferedAndRecorded，则先把已记录的 badData 写入 fallback；随后双向 io.Copy 进行转发。",
            ],
            "code_refs": {
                "impl": ["internal/node/fallback.go"],
                "tests": ["internal/node/fallback_test.go"],
                "docs": ["doc/FALLBACK.md"],
            },
        },
    ]

    results = []
    for item in checks:
        r = run_cmd(item["cmd"], timeout_s=600)
        r["name"] = item["name"]
        r["relates_to"] = item["relates_to"]
        out_text = (r.get("stdout") or "") + (r.get("stderr") or "")
        r["tests_run"] = parse_go_test_names(out_text)
        results.append(r)

    payload = {
        "generated_at": now_local_str(),
        "go_version": (go_ver.get("stdout") or "").strip(),
        "checks": results,
        "check_defs": checks,
    }
    write_json(out_dir / "results.json", payload)

    # Copy-friendly summary
    defs_by_name = {c["name"]: c for c in checks}
    lines: list[str] = []
    lines.append(f"Generated at: {payload['generated_at']}")
    lines.append(f"Go: {payload['go_version']}")
    lines.append("")
    for r in results:
        cdef = defs_by_name.get(r.get("name", ""), {})
        cmd_s = " ".join(r.get("cmd") or [])
        dur = float(r.get("duration_s") or 0.0)
        lines.append(f"- {r.get('name')}: exit={r.get('exit_code')} dur={dur:.2f}s")
        lines.append(f"  relates_to: {r.get('relates_to')}")
        tests_run = r.get("tests_run") or []
        if tests_run:
            lines.append(f"  tests_run({len(tests_run)}): {', '.join(tests_run)}")
        claims = cdef.get("claims") or []
        if claims:
            for cl in claims:
                lines.append(f"  claim: {cl}")
        lines.append(f"  cmd: {cmd_s}")
    lines.append("")
    write_text(out_dir / "summary.txt", "\n".join(lines))

    # HTML report
    rows = []
    for r in results:
        badge = "ok" if r.get("exit_code") == 0 else "fail"
        badge_text = "PASS" if badge == "ok" else "FAIL"
        dur = float(r.get("duration_s") or 0.0)
        tests_run = r.get("tests_run") or []
        rows.append(
            "<tr>"
            f"<td>{esc(r.get('name',''))}</td>"
            f"<td><span class=\"badge {badge}\">{badge_text}</span></td>"
            f"<td>{dur:.2f}</td>"
            f"<td>{esc(r.get('relates_to',''))}</td>"
            f"<td>{len(tests_run)}</td>"
            f"<td><code>{esc(' '.join(r.get('cmd') or []))}</code></td>"
            "</tr>"
        )

    details = []
    for r in results:
        cdef = defs_by_name.get(r.get("name", ""), {})
        badge = "ok" if r.get("exit_code") == 0 else "fail"
        badge_text = "PASS" if badge == "ok" else "FAIL"
        out_text = (r.get("stdout") or "") + (r.get("stderr") or "")
        out_text = out_text.strip() + "\n"
        tests_run = r.get("tests_run") or []

        claims = cdef.get("claims") or []
        algo = cdef.get("algorithm") or []
        evidence_links = cdef.get("evidence_links") or []
        demo = cdef.get("demo") or {}
        code_refs = cdef.get("code_refs") or {}

        claims_html = "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in claims) + "</ul>" if claims else ""
        algo_html = "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in algo) + "</ul>" if algo else ""
        tests_html = (
            "<ul>" + "".join(f"<li><code>{esc(t)}</code></li>" for t in tests_run) + "</ul>"
            if tests_run
            else "<span class=\"badge warn\">(no test names parsed; check output below)</span>"
        )
        links_html = (
            "<ul>" + "".join(f"<li><code>{esc(x)}</code></li>" for x in evidence_links) + "</ul>"
            if evidence_links
            else ""
        )

        demo_blocks: list[str] = []
        if demo:
            demo_blocks.append("<div class=\"card\"><h2>过程性示例（可截图/可复制）</h2>")
            for k, v in demo.items():
                demo_blocks.append(f"<div class=\"small\"><b>{esc(k)}</b></div>")
                if isinstance(v, dict) and ("hexdump" in v or "wire_hexdump" in v):
                    hexdump_key = "hexdump" if "hexdump" in v else "wire_hexdump"
                    hexd = str(v.get(hexdump_key) or "")
                    meta = {kk: vv for kk, vv in v.items() if kk != hexdump_key}
                    demo_blocks.append("<div class=\"small\">meta:</div>")
                    demo_blocks.append(f"<pre>{esc(json.dumps(meta, ensure_ascii=False, indent=2))}</pre>")
                    demo_blocks.append("<div class=\"small\">hexdump:</div>")
                    demo_blocks.append(f"<pre>{esc(hexd)}</pre>")
                else:
                    demo_blocks.append(f"<pre>{esc(json.dumps(v, ensure_ascii=False, indent=2))}</pre>")
            demo_blocks.append("</div>")

        code_blocks: list[str] = []
        for sec_name, files in (("impl", code_refs.get("impl") or []), ("tests", code_refs.get("tests") or []), ("docs", code_refs.get("docs") or [])):
            for rel in files:
                try:
                    content = read_rel(rel)
                except Exception as e:  # noqa: BLE001
                    content = f"[failed to read {rel}: {e}]"
                title = f"{sec_name} source"
                code_blocks.append(render_code_details(title=title, rel_path=rel, content=content))

        parts: list[str] = []
        parts.append("<div class=\"card\">")
        parts.append(f"<h2>{esc(r.get('name',''))} <span class=\"badge {badge}\">{badge_text}</span></h2>")
        parts.append(f"<div class=\"small\">relates_to: {esc(r.get('relates_to',''))}</div>")
        if claims_html:
            parts.append("<div class=\"small\"><b>要证明的结论（Claims）</b></div>")
            parts.append(claims_html)
        if algo_html:
            parts.append("<div class=\"small\"><b>采用的算法/机制（Algorithm）</b></div>")
            parts.append(algo_html)
        if links_html:
            parts.append("<div class=\"small\"><b>可截图的扩展证据（Links）</b></div>")
            parts.append(links_html)
        parts.append("<div class=\"small\"><b>本次运行到的测试用例（来自 -v 输出）</b></div>")
        parts.append(tests_html)
        parts.append(f"<div class=\"small\"><code>{esc(' '.join(r.get('cmd') or []))}</code></div>")
        parts.append("<details class=\"card\"><summary><b>go test 原始输出</b></summary>")
        parts.append(f"<pre>{esc(out_text)}</pre>")
        parts.append("</details>")
        parts.append("".join(demo_blocks))
        parts.append("".join(code_blocks))
        parts.append("</div>")
        details.append("".join(parts))

    body = (
        "<h1>04 Go 单元测试留痕（握手/分帧/UoT/回落等）</h1>"
        "<div class=\"card\">"
        "<div class=\"small\">"
        "目标：不仅保留 PASS/FAIL，还要回答“为什么能证明成功”。本报告对每个模块给出："
        "<br/>1) 要证明的结论（Claims）"
        "<br/>2) 算法/机制说明（Algorithm）"
        "<br/>3) 测试过程证据（-v 输出列出具体 test）"
        "<br/>4) 支撑代码（实现与测试源码，可展开复制）"
        "</div>"
        "<table>"
        f"<tr><th>Go version</th><td><code>{esc(payload['go_version'])}</code></td></tr>"
        f"<tr><th>results.json</th><td><code>out/results.json</code></td></tr>"
        f"<tr><th>summary.txt</th><td><code>out/summary.txt</code></td></tr>"
        "</table>"
        "</div>"
        "<div class=\"card\">"
        "<h2>汇总</h2>"
        "<table>"
        "<tr><th>check</th><th>status</th><th>dur(s)</th><th>relates_to</th><th>#tests</th><th>cmd</th></tr>"
        + "".join(rows)
        + "</table>"
        "</div>"
        + "".join(details)
    )
    write_text(out_dir / "report.html", html_page("04 Go 单元测试留痕", body))

    print(f"Wrote {out_dir / 'report.html'}")
    print(f"Wrote {out_dir / 'results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
