#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

import sys


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "out"
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "README.txt").write_text(
        "TODO: replace this template with a real evidence script.\n",
        encoding="utf-8",
    )
    print(f"Wrote {out_dir / 'README.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

