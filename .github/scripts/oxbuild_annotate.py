#!/usr/bin/env python3
"""
.github/scripts/oxbuild_annotate.py
=====================================
Reads the Oxbuild JSON report and emits GitHub annotations
for violations so they appear inline in the PR diff.

Usage:
    python oxbuild_annotate.py /tmp/oxbuild-report.json
"""

import json
import sys
from pathlib import Path


def main():
    if len(sys.argv) < 2:
        print("Usage: oxbuild_annotate.py <report.json>")
        sys.exit(0)

    report_path = Path(sys.argv[1])
    if not report_path.exists():
        print("Report not found — skipping annotations")
        sys.exit(0)

    try:
        report = json.loads(report_path.read_text())
    except json.JSONDecodeError:
        print("Could not parse report JSON")
        sys.exit(0)

    for file_result in report.get("files", []):
        filepath   = file_result.get("file", "unknown")
        violations = file_result.get("violations", [])

        for v in violations:
            level   = "error" if v["severity"] in ("CRITICAL", "HIGH") else "warning"
            title   = f"[{v['severity']}] {v['regulation']}: {v['title']}"
            message = f"{v.get('description','')} Fix: {v['remediation']}"
            print(f"::{level} file={filepath},title={title}::{message}")


if __name__ == "__main__":
    main()