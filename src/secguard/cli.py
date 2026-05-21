"""Secrets-scanner CLI for pre-commit / CI use.

    secguard-scan path/to/file ...        # scan specific files
    secguard-scan --staged                # scan files staged in git
    git diff --cached --name-only -z | xargs -0 secguard-scan

Exits non-zero when any secret is found, so it fails a commit or a CI job.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from secguard.scanner import scan_text


def _staged_files() -> list[str]:
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, check=False,
        )
        return [f for f in out.stdout.splitlines() if f.strip()]
    except FileNotFoundError:
        return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan files for committed secrets.")
    parser.add_argument("files", nargs="*", help="Files to scan.")
    parser.add_argument("--staged", action="store_true", help="Scan git-staged files.")
    args = parser.parse_args(argv)

    files = list(args.files)
    if args.staged:
        files += _staged_files()
    if not files:
        print("no files to scan", file=sys.stderr)
        return 0

    total = 0
    for f in files:
        p = Path(f)
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for finding in scan_text(text):
            total += 1
            print(f"{f}:{finding.line}:{finding.column}: {finding.rule}: {finding.redacted}")

    if total:
        print(f"\nsecguard: {total} potential secret(s) found", file=sys.stderr)
        return 1
    print("secguard: no secrets found", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
