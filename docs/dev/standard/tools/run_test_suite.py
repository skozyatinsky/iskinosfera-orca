#!/usr/bin/env python3
# ======================================================================
# run_test_suite.py — версия 2.0
# Изолированный pytest-runner с JUnit accounting и cleanup descendants.
# ======================================================================

"""Canonical isolated pytest runner.

Properties:
- external pytest plugins are disabled;
- test collection happens once;
- every collected node id runs in an isolated subprocess chunk;
- accounting is read from JUnit XML, never from human stdout;
- detached descendants are identified by a unique inherited token and killed;
- both ``runner.py -q`` and ``runner.py -- -q`` are accepted.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from junit_evidence import clone_testcases, node_ids_sha256, parse_junit, write_canonical_junit

try:
    import psutil
except ImportError:  # pragma: no cover - fail-closed path is tested by behavior
    psutil = None

PROCESS_TOKEN_ENV = "APS_TEST_RUNNER_TOKEN"


def _env(token: str) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env.setdefault("PYTHONHASHSEED", "0")
    env[PROCESS_TOKEN_ENV] = token
    tools_dir = str(Path(__file__).resolve().parent)
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = tools_dir if not existing_pythonpath else tools_dir + os.pathsep + existing_pythonpath
    return env


def _token_processes(token: str) -> list[Any]:
    if psutil is None:
        return []
    matches: list[Any] = []
    current_pid = os.getpid()
    for process in psutil.process_iter(attrs=["pid"]):
        if process.pid == current_pid:
            continue
        try:
            if process.environ().get(PROCESS_TOKEN_ENV) == token:
                matches.append(process)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return matches


def _kill_processes(processes: list[Any]) -> list[int]:
    if psutil is None:
        return []
    unique = {process.pid: process for process in processes if process.pid != os.getpid()}
    for process in unique.values():
        try:
            process.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _, alive = psutil.wait_procs(list(unique.values()), timeout=2)
    for process in alive:
        try:
            process.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    _, still_alive = psutil.wait_procs(alive, timeout=3)
    return sorted(process.pid for process in still_alive if process.is_running())


def _terminate_process_tree(proc: subprocess.Popen[object], token: str) -> list[int]:
    """Terminate root, recursive descendants and detached token descendants."""
    candidates: list[Any] = []
    if psutil is not None:
        try:
            root = psutil.Process(proc.pid)
            candidates.extend(root.children(recursive=True))
            candidates.append(root)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        candidates.extend(_token_processes(token))
        survivors = _kill_processes(candidates)
        survivors.extend(_kill_processes(_token_processes(token)))
        return sorted(set(survivors))

    # Fail-closed fallback for minimal environments.
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return []


def _cleanup_token(token: str) -> list[int]:
    if psutil is None:
        return []
    survivors = _kill_processes(_token_processes(token))
    time.sleep(0.05)
    survivors.extend(process.pid for process in _token_processes(token))
    return sorted(set(survivors))


def _run(cmd: list[str], *, cwd: Path, timeout: int) -> tuple[subprocess.CompletedProcess[str] | None, list[int]]:
    token = uuid.uuid4().hex
    with tempfile.TemporaryFile(mode="w+b") as log:
        kwargs: dict[str, object] = {
            "cwd": cwd,
            "env": _env(token),
            "stdout": log,
            "stderr": subprocess.STDOUT,
        }
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(cmd, **kwargs)
        timed_out = False
        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            survivors = _terminate_process_tree(proc, token)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                survivors = sorted(set(survivors + _terminate_process_tree(proc, token)))
            returncode = 124
        log.flush()
        log.seek(0)
        output = log.read().decode("utf-8", errors="replace")
    survivors = sorted(set((survivors if timed_out else []) + _cleanup_token(token)))
    if timed_out:
        if output:
            print(output, end="" if output.endswith("\n") else "\n")
        print(f"TEST_CHUNK_TIMEOUT seconds={timeout} command={cmd!r}", file=sys.stderr)
        if survivors:
            print(f"TEST_PROCESS_CLEANUP_FAILED pids={survivors}", file=sys.stderr)
        return None, survivors
    return subprocess.CompletedProcess(cmd, returncode, stdout=output, stderr=""), survivors


def _collect(root: Path, pytest_args: list[str], timeout: int) -> list[str] | None:
    cmd = [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", *pytest_args]
    proc, survivors = _run(cmd, cwd=root, timeout=timeout)
    if survivors:
        print(f"TEST_PROCESS_CLEANUP_FAILED pids={survivors}", file=sys.stderr)
        return None
    if proc is None:
        return None
    if proc.returncode != 0:
        if proc.stdout:
            print(proc.stdout, end="" if proc.stdout.endswith("\n") else "\n")
        print(f"TEST_COLLECTION_FAILED exit_code={proc.returncode}", file=sys.stderr)
        return None
    node_ids: list[str] = []
    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if "::" in line and not line.startswith(("<", "=")):
            node_ids.append(line)
    if not node_ids:
        print("TEST_COLLECTION_FAILED no node ids collected", file=sys.stderr)
        return None
    if len(node_ids) != len(set(node_ids)):
        print("TEST_COLLECTION_FAILED duplicate node ids", file=sys.stderr)
        return None
    return node_ids


def _strip_runner_owned_args(tokens: list[str]) -> list[str]:
    result: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token == "--":
            continue
        if token in {"-q", "--quiet"}:
            continue
        if token in {"--junitxml", "--junit-xml"}:
            skip_next = True
            continue
        if token.startswith("--junitxml=") or token.startswith("--junit-xml="):
            continue
        result.append(token)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--chunk-size", type=int, default=25)
    parser.add_argument("--chunk-timeout-seconds", type=int, default=60)
    parser.add_argument("--collect-timeout-seconds", type=int, default=120)
    parser.add_argument("--timeout-seconds", type=int, default=None)
    parser.add_argument("--summary-json", default=None)
    parser.add_argument("--junit-xml", default=None, help="export one canonical full-suite JUnit XML")
    args, pytest_args = parser.parse_known_args()

    if args.chunk_size < 1:
        parser.error("--chunk-size must be >= 1")
    if psutil is None:
        print("TEST_RUNNER_DEPENDENCY_MISSING: psutil is required for detached descendant cleanup", file=sys.stderr)
        return 2

    root = Path(args.root).resolve()
    chunk_timeout = args.timeout_seconds or args.chunk_timeout_seconds
    passthrough = _strip_runner_owned_args(pytest_args)
    started = time.monotonic()
    node_ids = _collect(root, passthrough, args.collect_timeout_seconds)
    if node_ids is None:
        return 2

    total = len(node_ids)
    completed = 0
    aggregate = {key: 0 for key in (
        "passed", "failed", "skipped", "xfailed", "xpassed", "errors", "unexpected_skipped"
    )}
    initial = [node_ids[i:i + args.chunk_size] for i in range(0, total, args.chunk_size)]
    queue: list[tuple[list[str], str]] = [(chunk, f"{i + 1}/{len(initial)}") for i, chunk in enumerate(initial)]
    attempt = 0
    canonical_cases = []

    with tempfile.TemporaryDirectory(prefix="aps_junit_") as junit_dir:
        while queue:
            chunk, label = queue.pop(0)
            attempt += 1
            first = node_ids.index(chunk[0]) + 1
            print(f"TEST_CHUNK_START label={label} attempt={attempt} nodes={len(chunk)} range={first}-{first + len(chunk) - 1}", flush=True)
            junit_path = Path(junit_dir) / f"chunk_{attempt}.xml"
            cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "pytest_junit_evidence_plugin", f"--junitxml={junit_path}", *chunk]
            proc, survivors = _run(cmd, cwd=root, timeout=chunk_timeout)
            if survivors:
                print(f"TEST_PROCESS_CLEANUP_FAILED pids={survivors}", file=sys.stderr)
                return 125
            if proc is None:
                if len(chunk) > 1:
                    middle = len(chunk) // 2
                    left, right = chunk[:middle], chunk[middle:]
                    print(f"TEST_CHUNK_SPLIT label={label} nodes={len(chunk)} into={len(left)}+{len(right)}", flush=True)
                    queue.insert(0, (right, f"{label}.R"))
                    queue.insert(0, (left, f"{label}.L"))
                    continue
                print(f"SEGMENTED_PYTEST_SUMMARY total={total} completed={completed} accounted={sum(aggregate.values())} passed={aggregate['passed']} failed={max(aggregate['failed'], 1)} skipped={aggregate['skipped']} xfailed={aggregate['xfailed']} xpassed={aggregate['xpassed']} errors={aggregate['errors']} unexpected_skipped={aggregate['unexpected_skipped']} status=TIMEOUT")
                return 124
            output = proc.stdout or ""
            print(output, end="" if output.endswith("\n") else "\n")
            if not junit_path.exists():
                print("TEST_JUNIT_MISSING", file=sys.stderr)
                return 3
            analysis = parse_junit(junit_path, require_node_ids=True)
            counts = analysis.summary
            if counts["total"] != len(chunk):
                print(f"TEST_ACCOUNTING_FAILED chunk={label} expected={len(chunk)} junit_total={counts['total']}", file=sys.stderr)
                return 3
            if analysis.missing_node_id_count or analysis.duplicate_node_ids:
                print(f"TEST_JUNIT_NODE_ID_INVALID chunk={label} missing={analysis.missing_node_id_count} duplicates={list(analysis.duplicate_node_ids)}", file=sys.stderr)
                return 3
            if set(analysis.node_ids) != set(chunk):
                print(f"TEST_JUNIT_NODE_SET_MISMATCH chunk={label}", file=sys.stderr)
                return 3
            canonical_cases.extend(clone_testcases(junit_path))
            for key in aggregate:
                aggregate[key] += int(counts[key])
            completed += int(counts["total"])
            if proc.returncode != 0 or counts["failed"] or counts["errors"]:
                print(f"TEST_CHUNK_FAILED label={label} exit_code={proc.returncode}", file=sys.stderr)
                return proc.returncode or 1
            print(f"TEST_CHUNK_PASS label={label} completed={completed}/{total}", flush=True)

    duration = time.monotonic() - started
    if args.junit_xml:
        junit_output = Path(args.junit_xml)
        write_canonical_junit(canonical_cases, junit_output)
        final_analysis = parse_junit(junit_output, require_node_ids=True)
        if final_analysis.missing_node_id_count or final_analysis.duplicate_node_ids or set(final_analysis.node_ids) != set(node_ids):
            print("TEST_CANONICAL_JUNIT_INVALID", file=sys.stderr)
            return 3
    accounted = sum(aggregate[key] for key in ("passed", "failed", "skipped", "xfailed", "xpassed", "errors"))
    status = "PASS" if (
        completed == total
        and accounted == total
        and aggregate["failed"] == 0
        and aggregate["errors"] == 0
        and aggregate["xpassed"] == 0
        and aggregate["unexpected_skipped"] == 0
    ) else "FAIL"
    summary = {
        "total": total,
        "completed": completed,
        "accounted": accounted,
        **aggregate,
        "duration_seconds": round(duration, 3),
        "status": status,
    }
    if args.summary_json:
        summary_path = Path(args.summary_json)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("SEGMENTED_PYTEST_SUMMARY " + " ".join(f"{key}={value}" for key, value in summary.items()))
    if args.junit_xml:
        print(f"CANONICAL_JUNIT path={args.junit_xml} node_ids_sha256={node_ids_sha256(node_ids)}")
    if status != "PASS":
        print("TEST_ACCOUNTING_FAILED structured JUnit summary did not satisfy PASS policy", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
