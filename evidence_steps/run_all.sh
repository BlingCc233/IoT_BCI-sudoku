#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${root_dir}"

#python3 00_plan_alignment/run.py
python3 02_padding_custom_layout/run.py
python3 03_hamming1_analysis/run.py
python3 01_sudoku_codec_validation/run.py
python3 04_go_unit_test_logs/run.py
python3 05_baseline_comparison/run.py

echo
echo "Done. Open reports:"
echo "  - ${root_dir}/00_plan_alignment/out/report.html"
echo "  - ${root_dir}/02_padding_custom_layout/out/report.html"
echo "  - ${root_dir}/03_hamming1_analysis/out/report.html"
echo "  - ${root_dir}/01_sudoku_codec_validation/out/report.html"
echo "  - ${root_dir}/04_go_unit_test_logs/out/report.html"
echo "  - ${root_dir}/05_baseline_comparison/out/report.html"
