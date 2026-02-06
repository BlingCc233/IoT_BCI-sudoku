#!/usr/bin/env python3
"""Cross-region benchmark: local client + VPS server.

TCP protocols are tested directly against VPS public ports.
UDP protocols (DTLS/CoAP) use UDP-over-TCP relay when public UDP is restricted:
local UDP -> local socat -> remote socat(TCP) -> remote UDP loopback server.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import statistics
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ProtoPlan:
    name: str
    kind: str  # tcp | udp_tunnel
    tcp_port: Optional[int] = None
    udp_inner: Optional[int] = None
    relay_tcp: Optional[int] = None
    local_udp: Optional[int] = None


PROTO_PLANS = [
    ProtoPlan("iotbci-sudoku-pure-tcp", "tcp", tcp_port=21011),
    ProtoPlan("iotbci-sudoku-packed-tcp", "tcp", tcp_port=21012),
    ProtoPlan("pure-aead-tcp", "tcp", tcp_port=21013),
    ProtoPlan("dtls-psk-aes128gcm", "udp_tunnel", udp_inner=21114, relay_tcp=31114, local_udp=41114),
    ProtoPlan("coap-udp", "udp_tunnel", udp_inner=21115, relay_tcp=31115, local_udp=41115),
    ProtoPlan("mqtt-3.1.1-qos0-tls", "tcp", tcp_port=21016),
]


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())


def run_cmd(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess:
    cp = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout)
    if check and cp.returncode != 0:
        raise RuntimeError(
            f"command failed ({cp.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{cp.stdout}\n"
            f"stderr:\n{cp.stderr}"
        )
    return cp


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def make_expect_helper(path: Path) -> Path:
    script = textwrap.dedent(
        """\
        #!/usr/bin/expect -f
        set timeout -1
        if {$argc < 4} {
          puts stderr "usage: ssh_expect host user pass command"
          exit 2
        }
        set host [lindex $argv 0]
        set user [lindex $argv 1]
        set pass [lindex $argv 2]
        set cmd [lindex $argv 3]
        spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ${user}@${host} "$cmd"
        expect {
          -re "(?i)password:" { send "$pass\\r"; exp_continue }
          eof
        }
        """
    )
    write_text(path, script)
    path.chmod(0o755)
    return path


class SSHRunner:
    def __init__(
        self,
        host: str,
        user: str,
        password: Optional[str] = None,
        ssh_key: Optional[Path] = None,
        helper: Optional[Path] = None,
    ):
        self.host = host
        self.user = user
        self.password = password
        self.ssh_key = ssh_key
        self.helper = helper

    def _ssh_cmd(self, cmd: str) -> List[str]:
        if self.ssh_key is not None:
            return [
                "ssh",
                "-i",
                str(self.ssh_key),
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                f"{self.user}@{self.host}",
                cmd,
            ]
        if self.helper is None or self.password is None:
            raise RuntimeError("ssh runner requires either --ssh-key or (--password + expect helper)")
        return [str(self.helper), self.host, self.user, self.password, cmd]

    def run(self, cmd: str, timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess:
        cp = run_cmd(self._ssh_cmd(cmd), timeout=timeout, check=False)
        if check and cp.returncode != 0:
            raise RuntimeError(
                f"ssh command failed ({cp.returncode})\ncmd: {cmd}\nstdout:\n{cp.stdout}\nstderr:\n{cp.stderr}"
            )
        return cp


def extract_json_object(text: str) -> Dict[str, Any]:
    i = text.find("{")
    if i < 0:
        raise ValueError(f"no json object found in ssh output:\n{text}")
    jtxt = text[i:]
    return json.loads(jtxt)


def slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", s)


def median_or_none(vals: List[float]) -> Optional[float]:
    if not vals:
        return None
    return float(statistics.median(vals))


def start_remote_tcp_server(ssh: SSHRunner, remote_repo: str, remote_bin: str, proto: str, port: int, messages: int, size: int, timeout_s: int, tag: str) -> None:
    cmd = (
        "set -eu; "
        f"fuser -k {port}/tcp >/dev/null 2>&1 || true; "
        f"rm -f /tmp/{tag}_srv.*; "
        f"cd {shlex.quote(remote_repo)} && "
        f"setsid -f {shlex.quote(remote_bin)} -mode server -proto {shlex.quote(proto)} "
        f"-listen 0.0.0.0:{port} -messages {messages} -size {size} -timeout {timeout_s}s "
        f"-out /tmp/{tag}_srv.json >/tmp/{tag}_srv.out 2>/tmp/{tag}_srv.err </dev/null; "
        "sleep 1; "
        f"fuser {port}/tcp >/dev/null 2>&1"
    )
    ssh.run(cmd, timeout=120, check=True)


def start_remote_udp_server_and_relay(
    ssh: SSHRunner,
    remote_repo: str,
    remote_bin: str,
    proto: str,
    inner_port: int,
    relay_tcp_port: int,
    messages: int,
    size: int,
    timeout_s: int,
    tag: str,
) -> None:
    cmd = (
        "set -eu; "
        f"fuser -k {inner_port}/udp >/dev/null 2>&1 || true; "
        f"fuser -k {relay_tcp_port}/tcp >/dev/null 2>&1 || true; "
        f"rm -f /tmp/{tag}_srv.* /tmp/{tag}_relay.*; "
        f"cd {shlex.quote(remote_repo)} && "
        f"setsid -f {shlex.quote(remote_bin)} -mode server -proto {shlex.quote(proto)} "
        f"-listen 127.0.0.1:{inner_port} -messages {messages} -size {size} -timeout {timeout_s}s "
        f"-out /tmp/{tag}_srv.json >/tmp/{tag}_srv.out 2>/tmp/{tag}_srv.err </dev/null; "
        f"setsid -f socat TCP-LISTEN:{relay_tcp_port},reuseaddr,fork UDP:127.0.0.1:{inner_port} "
        f">/tmp/{tag}_relay.out 2>/tmp/{tag}_relay.err </dev/null; "
        "sleep 1; "
        f"fuser {inner_port}/udp >/dev/null 2>&1; "
        f"fuser {relay_tcp_port}/tcp >/dev/null 2>&1"
    )
    ssh.run(cmd, timeout=120, check=True)


def fetch_remote_server_json(ssh: SSHRunner, tag: str) -> Dict[str, Any]:
    cmd = (
        "set +e; "
        f"for i in $(seq 1 120); do "
        f"  if [ -s /tmp/{tag}_srv.json ]; then break; fi; "
        f"  sleep 1; "
        f"done; "
        f"if [ -s /tmp/{tag}_srv.json ]; then cat /tmp/{tag}_srv.json; exit 0; fi; "
        f"echo \"__NO_SERVER_JSON__\"; "
        f"ls -la /tmp/{tag}_srv.* /tmp/{tag}_relay.* 2>/dev/null || true; "
        f"echo \"__SERVER_STDERR__\"; cat /tmp/{tag}_srv.err 2>/dev/null || true; "
        f"echo \"__SERVER_STDOUT__\"; cat /tmp/{tag}_srv.out 2>/dev/null || true; "
        "exit 1"
    )
    cp = ssh.run(cmd, timeout=150, check=False)
    if cp.returncode != 0:
        raise RuntimeError(f"server json missing for tag={tag}\nstdout:\n{cp.stdout}\nstderr:\n{cp.stderr}")
    return extract_json_object(cp.stdout)


def cleanup_remote(ssh: SSHRunner, tcp_port: Optional[int] = None, udp_port: Optional[int] = None, relay_port: Optional[int] = None) -> None:
    parts: List[str] = []
    if tcp_port is not None:
        parts.append(f"fuser -k {tcp_port}/tcp >/dev/null 2>&1 || true")
    if udp_port is not None:
        parts.append(f"fuser -k {udp_port}/udp >/dev/null 2>&1 || true")
    if relay_port is not None:
        parts.append(f"fuser -k {relay_port}/tcp >/dev/null 2>&1 || true")
    if not parts:
        return
    ssh.run("; ".join(parts), timeout=60, check=False)


def run_client_local(repo_root: Path, proto: str, server_addr: str, messages: int, size: int, timeout_s: int, out_json: Path) -> Tuple[Dict[str, Any], subprocess.CompletedProcess]:
    cmd = [
        "go",
        "run",
        "./cmd/iotbci-netbench",
        "-mode",
        "client",
        "-proto",
        proto,
        "-server",
        server_addr,
        "-messages",
        str(messages),
        "-size",
        str(size),
        "-timeout",
        f"{timeout_s}s",
        "-out",
        str(out_json),
    ]
    cp = run_cmd(cmd, cwd=repo_root, timeout=timeout_s + 60, check=False)
    if not out_json.exists():
        raise RuntimeError(f"client output json missing: {out_json}\nstdout:\n{cp.stdout}\nstderr:\n{cp.stderr}")
    report = json.loads(out_json.read_text(encoding="utf-8"))
    return report, cp


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="")
    ap.add_argument("--ssh-key", default="")
    ap.add_argument("--remote-repo", default="/root/IoT_BCI-sudoku")
    ap.add_argument("--remote-bin", default="/root/IoT_BCI-sudoku/iotbci-netbench")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--messages", type=int, default=80)
    ap.add_argument("--size", type=int, default=256)
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--out-dir", default="evidence_steps/07_cross_region_benchmark/out")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    out_dir = (repo_root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    ssh_key: Optional[Path] = None
    if args.ssh_key:
        ssh_key = Path(args.ssh_key).expanduser().resolve()
        if not ssh_key.exists():
            raise FileNotFoundError(f"ssh key not found: {ssh_key}")
    helper: Optional[Path] = None
    password = args.password.strip()
    if ssh_key is None:
        if not password:
            raise RuntimeError("provide --ssh-key or --password")
        helper = make_expect_helper(out_dir / ".ssh_expect_helper")
    ssh = SSHRunner(args.host, args.user, password=password or None, ssh_key=ssh_key, helper=helper)

    rows: List[Dict[str, Any]] = []

    for r in range(1, args.runs + 1):
        round_dir = out_dir / "runs" / f"r{r}"
        round_dir.mkdir(parents=True, exist_ok=True)
        offset = (r - 1) * 100

        for plan in PROTO_PLANS:
            proto = plan.name
            tag = f"r{r}_{slug(proto)}"
            print(f"[r{r}] {proto}")

            local_relay_proc: Optional[subprocess.Popen] = None
            server_report: Optional[Dict[str, Any]] = None
            client_report: Optional[Dict[str, Any]] = None
            cp: Optional[subprocess.CompletedProcess] = None
            transport_note = "direct"
            server_addr = ""
            tcp_port: Optional[int] = None
            inner_udp_port: Optional[int] = None
            relay_port: Optional[int] = None
            local_udp_port: Optional[int] = None

            try:
                if plan.kind == "tcp":
                    assert plan.tcp_port is not None
                    tcp_port = plan.tcp_port + offset
                    start_remote_tcp_server(
                        ssh,
                        args.remote_repo,
                        args.remote_bin,
                        proto,
                        tcp_port,
                        args.messages,
                        args.size,
                        args.timeout,
                        tag,
                    )
                    server_addr = f"{args.host}:{tcp_port}"
                else:
                    assert plan.udp_inner is not None
                    assert plan.relay_tcp is not None
                    assert plan.local_udp is not None
                    inner = plan.udp_inner + offset
                    relay = plan.relay_tcp + offset
                    local_udp = plan.local_udp + offset
                    inner_udp_port = inner
                    relay_port = relay
                    local_udp_port = local_udp

                    start_remote_udp_server_and_relay(
                        ssh,
                        args.remote_repo,
                        args.remote_bin,
                        proto,
                        inner,
                        relay,
                        args.messages,
                        args.size,
                        args.timeout,
                        tag,
                    )

                    # local UDP->TCP relay
                    run_cmd(["pkill", "-f", f"socat UDP-LISTEN:{local_udp}"], check=False)
                    local_relay_proc = subprocess.Popen(
                        [
                            "socat",
                            f"UDP-LISTEN:{local_udp},reuseaddr,fork",
                            f"TCP:{args.host}:{relay}",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    time.sleep(1)
                    server_addr = f"127.0.0.1:{local_udp}"
                    transport_note = "udp-over-tcp-relay"

                client_json = round_dir / f"{proto}_client.json"
                client_report, cp = run_client_local(
                    repo_root,
                    proto,
                    server_addr,
                    args.messages,
                    args.size,
                    args.timeout,
                    client_json,
                )

                server_report = fetch_remote_server_json(ssh, tag)
                (round_dir / f"{proto}_server.json").write_text(json.dumps(server_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

            except Exception as e:  # noqa: BLE001
                err = str(e)
                if client_report is None:
                    client_report = {
                        "generated_at": now_iso(),
                        "role": "client",
                        "proto": proto,
                        "server_addr": server_addr,
                        "result": {},
                        "error": err,
                    }
                    (round_dir / f"{proto}_client.json").write_text(
                        json.dumps(client_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                    )
                if server_report is None:
                    server_report = {
                        "generated_at": now_iso(),
                        "role": "server",
                        "proto": proto,
                        "error": err,
                    }
                    (round_dir / f"{proto}_server.json").write_text(
                        json.dumps(server_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
                    )

            finally:
                if local_relay_proc is not None:
                    local_relay_proc.terminate()
                    try:
                        local_relay_proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        local_relay_proc.kill()
                if local_udp_port is not None:
                    run_cmd(["pkill", "-f", f"socat UDP-LISTEN:{local_udp_port}"], check=False)
                cleanup_remote(ssh, tcp_port=tcp_port, udp_port=inner_udp_port, relay_port=relay_port)

            cres = (client_report or {}).get("result") or {}
            sres = (server_report or {}).get("result") or {}
            rows.append(
                {
                    "run": r,
                    "proto": proto,
                    "transport_note": transport_note,
                    "server_addr_used": server_addr,
                    "client_error": (client_report or {}).get("error", ""),
                    "server_error": (server_report or {}).get("error", ""),
                    "avg_rtt_ms": float(cres.get("avg_rtt_ms") or 0.0),
                    "p95_rtt_ms": float(cres.get("p95_rtt_ms") or 0.0),
                    "overhead_ratio": float(cres.get("overhead_ratio") or 0.0),
                    "client_peak_heap_alloc_bytes": int(cres.get("peak_heap_alloc_bytes") or 0),
                    "client_peak_heap_inuse_bytes": int(cres.get("peak_heap_inuse_bytes") or 0),
                    "client_peak_sys_bytes": int(cres.get("peak_sys_bytes") or 0),
                    "client_phase_delta_heap_alloc_bytes": int(cres.get("phase_delta_heap_alloc_bytes") or 0),
                    "client_phase_delta_heap_inuse_bytes": int(cres.get("phase_delta_heap_inuse_bytes") or 0),
                    "client_phase_delta_sys_bytes": int(cres.get("phase_delta_sys_bytes") or 0),
                    "client_duration_ms": float(cres.get("duration_ms") or 0.0),
                    "server_peak_heap_alloc_bytes": int(sres.get("peak_heap_alloc_bytes") or 0),
                    "server_peak_heap_inuse_bytes": int(sres.get("peak_heap_inuse_bytes") or 0),
                    "server_peak_sys_bytes": int(sres.get("peak_sys_bytes") or 0),
                    "server_phase_delta_heap_alloc_bytes": int(sres.get("phase_delta_heap_alloc_bytes") or 0),
                    "server_phase_delta_heap_inuse_bytes": int(sres.get("phase_delta_heap_inuse_bytes") or 0),
                    "server_phase_delta_sys_bytes": int(sres.get("phase_delta_sys_bytes") or 0),
                }
            )

    # Aggregate medians from successful rows.
    by_proto: Dict[str, List[Dict[str, Any]]] = {}
    for row in rows:
        by_proto.setdefault(row["proto"], []).append(row)

    medians: Dict[str, Dict[str, Any]] = {}
    for proto, items in by_proto.items():
        ok = [x for x in items if not x["client_error"]]
        medians[proto] = {
            "n_total": len(items),
            "n_ok": len(ok),
            "transport_note": (ok[0]["transport_note"] if ok else items[0]["transport_note"]),
            "avg_rtt_ms": median_or_none([x["avg_rtt_ms"] for x in ok]),
            "p95_rtt_ms": median_or_none([x["p95_rtt_ms"] for x in ok]),
            "overhead_ratio": median_or_none([x["overhead_ratio"] for x in ok]),
            "client_peak_heap_alloc_bytes": median_or_none([float(x["client_peak_heap_alloc_bytes"]) for x in ok]),
            "client_peak_heap_inuse_bytes": median_or_none([float(x["client_peak_heap_inuse_bytes"]) for x in ok]),
            "client_peak_sys_bytes": median_or_none([float(x["client_peak_sys_bytes"]) for x in ok]),
            "client_phase_delta_heap_alloc_bytes": median_or_none([float(x["client_phase_delta_heap_alloc_bytes"]) for x in ok]),
            "client_phase_delta_heap_inuse_bytes": median_or_none([float(x["client_phase_delta_heap_inuse_bytes"]) for x in ok]),
            "client_phase_delta_sys_bytes": median_or_none([float(x["client_phase_delta_sys_bytes"]) for x in ok]),
            "client_mem_metric_bytes": median_or_none([float(x["client_phase_delta_heap_alloc_bytes"]) for x in ok]),
            "client_mem_metric_name": "phase_delta_heap_alloc_bytes",
            "server_peak_heap_alloc_bytes": median_or_none([float(x["server_peak_heap_alloc_bytes"]) for x in ok]),
            "server_peak_heap_inuse_bytes": median_or_none([float(x["server_peak_heap_inuse_bytes"]) for x in ok]),
            "server_peak_sys_bytes": median_or_none([float(x["server_peak_sys_bytes"]) for x in ok]),
            "server_phase_delta_heap_alloc_bytes": median_or_none([float(x["server_phase_delta_heap_alloc_bytes"]) for x in ok]),
            "server_phase_delta_heap_inuse_bytes": median_or_none([float(x["server_phase_delta_heap_inuse_bytes"]) for x in ok]),
            "server_phase_delta_sys_bytes": median_or_none([float(x["server_phase_delta_sys_bytes"]) for x in ok]),
        }

    def m(proto: str, key: str) -> Optional[float]:
        return medians.get(proto, {}).get(key)

    def lt(a: Optional[float], b: Optional[float]) -> Optional[bool]:
        if a is None or b is None:
            return None
        return a < b

    guard = {
        "pure_rtt_lt_dtls": lt(m("iotbci-sudoku-pure-tcp", "avg_rtt_ms"), m("dtls-psk-aes128gcm", "avg_rtt_ms")),
        "pure_rtt_lt_mqtt": lt(m("iotbci-sudoku-pure-tcp", "avg_rtt_ms"), m("mqtt-3.1.1-qos0-tls", "avg_rtt_ms")),
        "pure_mem_lt_dtls": lt(m("iotbci-sudoku-pure-tcp", "client_mem_metric_bytes"), m("dtls-psk-aes128gcm", "client_mem_metric_bytes")),
        "pure_mem_lt_mqtt": lt(m("iotbci-sudoku-pure-tcp", "client_mem_metric_bytes"), m("mqtt-3.1.1-qos0-tls", "client_mem_metric_bytes")),
        "packed_rtt_lt_dtls": lt(m("iotbci-sudoku-packed-tcp", "avg_rtt_ms"), m("dtls-psk-aes128gcm", "avg_rtt_ms")),
        "packed_rtt_lt_mqtt": lt(m("iotbci-sudoku-packed-tcp", "avg_rtt_ms"), m("mqtt-3.1.1-qos0-tls", "avg_rtt_ms")),
        "packed_mem_lt_dtls": lt(m("iotbci-sudoku-packed-tcp", "client_mem_metric_bytes"), m("dtls-psk-aes128gcm", "client_mem_metric_bytes")),
        "packed_mem_lt_mqtt": lt(m("iotbci-sudoku-packed-tcp", "client_mem_metric_bytes"), m("mqtt-3.1.1-qos0-tls", "client_mem_metric_bytes")),
    }

    summary = {
        "generated_at": now_iso(),
        "host": args.host,
        "runs": args.runs,
        "messages": args.messages,
        "payload_size": args.size,
        "notes": {
            "udp_transport": "DTLS/CoAP used udp-over-tcp relay due public UDP restriction on VPS",
            "mem_metric_for_guard": "phase_delta_heap_alloc_bytes",
            "phase_delta_heap_inuse_quantization": "phase_delta_heap_inuse_bytes is page-quantized (commonly 8192B steps); use phase_delta_heap_alloc_bytes for guard",
        },
        "rows": rows,
        "medians": medians,
        "guard": guard,
    }

    write_text(out_dir / "summary.json", json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    lines = [
        f"Cross-region benchmark summary ({args.host})",
        f"runs={args.runs}, messages={args.messages}, payload={args.size}B",
        "memory guard metric=phase_delta_heap_alloc_bytes; phase_delta_heap_inuse_bytes is page-quantized",
        "",
        "Medians by protocol:",
    ]
    for p in [x.name for x in PROTO_PLANS]:
        md = medians.get(p, {})
        lines.append(
            f"- {p}: avg_rtt_ms={md.get('avg_rtt_ms')}, p95_rtt_ms={md.get('p95_rtt_ms')}, "
            f"overhead={md.get('overhead_ratio')}, client_mem_metric({md.get('client_mem_metric_name')})={md.get('client_mem_metric_bytes')}, "
            f"client_peak_heap_inuse={md.get('client_peak_heap_inuse_bytes')}, "
            f"n_ok={md.get('n_ok')}/{md.get('n_total')}, transport={md.get('transport_note')}"
        )
    lines.append("")
    lines.append("Guard checks:")
    for k, v in guard.items():
        lines.append(f"- {k}: {v}")

    write_text(out_dir / "summary.txt", "\n".join(lines) + "\n")

    # Lightweight HTML report.
    rows_html = []
    for row in rows:
        rows_html.append(
            "<tr>"
            f"<td>{row['run']}</td>"
            f"<td><code>{row['proto']}</code></td>"
            f"<td>{row['transport_note']}</td>"
            f"<td>{row['avg_rtt_ms']:.6f}</td>"
            f"<td>{row['p95_rtt_ms']:.6f}</td>"
            f"<td>{row['overhead_ratio']:.6f}</td>"
            f"<td>{row['client_phase_delta_heap_alloc_bytes']}</td>"
            f"<td>{row['client_peak_heap_inuse_bytes']}</td>"
            f"<td>{row['client_error'] or 'OK'}</td>"
            "</tr>"
        )

    md_rows = []
    for p in [x.name for x in PROTO_PLANS]:
        md = medians.get(p, {})
        md_rows.append(
            "<tr>"
            f"<td><code>{p}</code></td>"
            f"<td>{md.get('transport_note')}</td>"
            f"<td>{md.get('avg_rtt_ms')}</td>"
            f"<td>{md.get('p95_rtt_ms')}</td>"
            f"<td>{md.get('overhead_ratio')}</td>"
            f"<td>{md.get('client_mem_metric_bytes')}</td>"
            f"<td>{md.get('client_peak_heap_inuse_bytes')}</td>"
            f"<td>{md.get('n_ok')}/{md.get('n_total')}</td>"
            "</tr>"
        )

    html = f"""<!doctype html>
<html lang=\"zh-CN\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Cross-region benchmark</title>
  <style>
    body {{ font-family: -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif; margin: 24px; line-height: 1.45; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0 24px; }}
    th,td {{ border: 1px solid #ddd; padding: 8px; font-size: 13px; }}
    th {{ background: #f5f5f5; text-align: left; }}
    code {{ background: #f2f2f2; padding: 1px 4px; border-radius: 4px; }}
    .note {{ color: #444; }}
  </style>
</head>
<body>
  <h1>跨国网络基准报告</h1>
  <p>host=<code>{args.host}</code>, runs={args.runs}, messages={args.messages}, payload={args.size}B</p>
  <p class=\"note\">UDP 受限处理：DTLS/CoAP 采用 <code>udp-over-tcp relay</code>。</p>
  <p class=\"note\">内存守卫口径：<code>phase_delta_heap_alloc_bytes</code>。<code>phase_delta_heap_inuse_bytes</code> 受页粒度量化影响（常见 8192B 台阶），仅作参考。</p>

  <h2>中位数汇总</h2>
  <table>
    <thead><tr><th>协议</th><th>路径</th><th>avg RTT(ms)</th><th>P95 RTT(ms)</th><th>overhead</th><th>client 内存指标(B)</th><th>client heap_inuse 峰值(B)</th><th>成功轮次</th></tr></thead>
    <tbody>
      {''.join(md_rows)}
    </tbody>
  </table>

  <h2>逐轮明细</h2>
  <table>
    <thead><tr><th>run</th><th>协议</th><th>路径</th><th>avg RTT</th><th>P95 RTT</th><th>overhead</th><th>client 内存指标</th><th>client heap_inuse 峰值</th><th>状态</th></tr></thead>
    <tbody>
      {''.join(rows_html)}
    </tbody>
  </table>

  <h2>Guard</h2>
  <pre>{json.dumps(guard, ensure_ascii=False, indent=2)}</pre>
</body>
</html>
"""
    write_text(out_dir / "report.html", html)

    print(f"[ok] wrote: {out_dir / 'summary.json'}")
    print(f"[ok] wrote: {out_dir / 'summary.txt'}")
    print(f"[ok] wrote: {out_dir / 'report.html'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
