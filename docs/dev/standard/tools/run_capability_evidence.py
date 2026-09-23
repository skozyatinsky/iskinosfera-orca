#!/usr/bin/env python3
# ======================================================================
# run_capability_evidence.py — версия 2.0
# Executes structured evidence and verifies runtime finding codes.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def host_platform() -> str:
    value = platform.system().lower()
    return {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(value, value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--case-id", action="append")
    parser.add_argument("--platform", choices=("darwin", "linux", "windows"), default=host_platform())
    args = parser.parse_args()
    root = Path(args.root).resolve()
    data = json.loads((root / "reference/capability_evidence.json").read_text())
    selected = set(args.case_id or [])
    results = []
    for case in data.get("cases", []):
        if selected and case.get("case_id") not in selected:
            continue
        command = [sys.executable, "-m", "pytest", "-q", "-s", case["pytest_node_id"]]
        required_platforms = case.get("required_platforms", [])
        if required_platforms and args.platform not in required_platforms:
            results.append({
                "case_id": case["case_id"], "capability_id": case["capability_id"],
                "rule_id": case.get("rule_id"), "polarity": case["polarity"],
                "pytest_node_id": case["pytest_node_id"],
                "expected_finding_code": case.get("expected_finding_code"),
                "finding_observed": False, "command": command, "exit_code": None,
                "expected_exit_code": case["expected_exit_code"], "status": "NOT_APPLICABLE",
                "reason_code": "CAPABILITY_EVIDENCE_PLATFORM_NOT_APPLICABLE",
                "current_platform": args.platform, "required_platforms": required_platforms,
                "output_sha256": hashlib.sha256(b"not-applicable").hexdigest(),
            })
            continue
        env = {**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_ADDOPTS": "-p no:cacheprovider"}
        proc = subprocess.run(command, cwd=root, capture_output=True, text=True, env=env)
        combined = proc.stdout + "\n" + proc.stderr
        expected_finding = case.get("expected_finding_code")
        exit_ok = proc.returncode == case["expected_exit_code"]
        finding_ok = True if not expected_finding else expected_finding in combined
        status = "PASS" if exit_ok and finding_ok else "FAIL"
        payload = combined.encode()
        results.append({
            "case_id": case["case_id"], "capability_id": case["capability_id"],
            "rule_id": case.get("rule_id"),
            "polarity": case["polarity"], "pytest_node_id": case["pytest_node_id"],
            "expected_finding_code": expected_finding, "finding_observed": finding_ok,
            "command": command, "exit_code": proc.returncode,
            "expected_exit_code": case["expected_exit_code"], "status": status,
            "output_sha256": hashlib.sha256(payload).hexdigest(),
        })
    report = {
        "schema_version": "2.0.0", "started_at": now(), "completed_at": now(),
        "total": len(results), "passed": sum(r["status"] == "PASS" for r in results),
        "not_applicable": sum(r["status"] == "NOT_APPLICABLE" for r in results),
        "failed": sum(r["status"] == "FAIL" for r in results),
        "status": "PASS" if results and all(r["status"] != "FAIL" for r in results) else "FAIL",
        "platform": args.platform,
        "results": results,
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
