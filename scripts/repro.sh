#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Reproducible one-command run for bench/evidence/dashboard/tex snippets.

Usage:
  scripts/repro.sh [flags]

Flags:
  -messages N     number of messages per scenario (default: 200)
  -size BYTES     payload size per message (default: 256)
  -timeout DUR    per-tool timeout, e.g. 30s (default: 30s)
  -out_dir DIR    output root (default: tmp/repro_out)
  -tex_out DIR    LaTeX snippet output dir (default: tex/generated)
  -no_attack      skip cmd/iotbci-attack
  -no_tex         skip cmd/iotbci-texgen
  -h, --help      show help

Outputs:
  <out_dir>/bench.json
  <out_dir>/evidence_out/evidence.json
  <out_dir>/dashboard_out/index.html
  <tex_out>/*.tex  (if not disabled)
EOF
}

messages=200
size=256
timeout=30s
out_dir=tmp/repro_out
tex_out=tex/generated
run_attack=1
run_tex=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    -messages)
      messages="${2:?missing value for -messages}"
      shift 2
      ;;
    -size)
      size="${2:?missing value for -size}"
      shift 2
      ;;
    -timeout)
      timeout="${2:?missing value for -timeout}"
      shift 2
      ;;
    -out_dir)
      out_dir="${2:?missing value for -out_dir}"
      shift 2
      ;;
    -tex_out)
      tex_out="${2:?missing value for -tex_out}"
      shift 2
      ;;
    -no_attack)
      run_attack=0
      shift
      ;;
    -no_tex)
      run_tex=0
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown flag: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"

mkdir -p "${out_dir}"

bench_json="${out_dir}/bench.json"
evidence_dir="${out_dir}/evidence_out"
attack_json="${out_dir}/attack_report.json"
dashboard_dir="${out_dir}/dashboard_out"

echo "==> micro-bench -> ${bench_json}"
go run ./cmd/iotbci-bench -messages "${messages}" -size "${size}" -timeout "${timeout}" -out "${bench_json}"

echo "==> evidence (loopback TCP/UDP) -> ${evidence_dir}"
go run ./cmd/iotbci-evidence -out_dir "${evidence_dir}" -messages "${messages}" -size "${size}" -timeout "${timeout}"

attack_args=()
if [[ "${run_attack}" == "1" ]]; then
  echo "==> attack simulation -> ${attack_json}"
  go run ./cmd/iotbci-attack -timeout 10s -out "${attack_json}"
  attack_args=(-attack "${attack_json}")
else
  echo "==> attack simulation skipped (-no_attack)"
fi

echo "==> dashboard -> ${dashboard_dir}/index.html"
go run ./cmd/iotbci-dashboard -bench "${bench_json}" -evidence "${evidence_dir}/evidence.json" "${attack_args[@]}" -out_dir "${dashboard_dir}"

if [[ "${run_tex}" == "1" ]]; then
  echo "==> LaTeX snippets -> ${tex_out}"
  go run ./cmd/iotbci-texgen -bench "${bench_json}" -evidence "${evidence_dir}/evidence.json" -out_dir "${tex_out}"
else
  echo "==> LaTeX snippets skipped (-no_tex)"
fi

echo
echo "Done:"
echo "  - Open: ${dashboard_dir}/index.html"
echo "  - Bench JSON: ${bench_json}"
echo "  - Evidence JSON: ${evidence_dir}/evidence.json"
