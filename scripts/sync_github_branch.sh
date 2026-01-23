#!/usr/bin/env bash
set -euo pipefail

# Sync a public-facing branch from a private branch by removing sensitive paths.
#
# Typical workflow:
#   1) Maintain `main` for Gitea (full repo, including thesis).
#   2) Maintain `github` for GitHub (template + public code only).
#
# Usage:
#   scripts/sync_github_branch.sh [source_branch] [target_branch]
#
# Default:
#   source_branch=main
#   target_branch=github

SOURCE_BRANCH="${1:-main}"
TARGET_BRANCH="${2:-github}"

SENSITIVE_PATHS=(
  "tex/main.tex"
  "tex/chapter"
  "tex/misc"
  "tex/generated"
  "tex/pic/generated"
  "attack_report.json"
  "bench.json"
  "bench*.json"
  "evidence_out"
  "report_out"
)

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is not clean; commit/stash first" >&2
  exit 1
fi

if git show-ref --verify --quiet "refs/heads/${TARGET_BRANCH}"; then
  git checkout "${TARGET_BRANCH}"
else
  git checkout -b "${TARGET_BRANCH}"
fi

git reset --hard "${SOURCE_BRANCH}"

export IOTBCI_SENSITIVE_PATHS
IOTBCI_SENSITIVE_PATHS="$(printf '%s\n' "${SENSITIVE_PATHS[@]}")"
python3 - <<'PY'
import glob
import os
import shutil
from pathlib import Path

patterns = os.environ.get("IOTBCI_SENSITIVE_PATHS", "").splitlines()
repo_root = Path(".").resolve()

for pattern in patterns:
    if not pattern.strip():
        continue
    for match in glob.glob(pattern):
        path = Path(match)
        try:
            resolved = path.resolve()
        except FileNotFoundError:
            continue
        if repo_root not in resolved.parents and resolved != repo_root:
            raise SystemExit(f"refusing to delete outside repo: {path}")
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
PY
unset IOTBCI_SENSITIVE_PATHS

git add -A
git commit -m "sync ${TARGET_BRANCH} from ${SOURCE_BRANCH} (remove private thesis)" || true

echo
echo "Next:"
echo "  git push <github-remote> ${TARGET_BRANCH}"
