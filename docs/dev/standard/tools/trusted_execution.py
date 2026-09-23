#!/usr/bin/env python3
# ======================================================================
# trusted_execution.py — версия 3.0
# Immutable candidate execution with secret-free environment and cleanup.
# ======================================================================
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import platform
import re
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sandbox_certification import certification_state  # noqa: E402

TRUSTED_GIT_EXECUTABLE = str(Path("/usr/bin/git").resolve()) if Path("/usr/bin/git").exists() else "git"

try:
    import psutil
except ImportError:  # pragma: no cover - fail-closed path
    psutil = None

PROCESS_TOKEN_ENV = "APS_CANDIDATE_PROCESS_TOKEN"
TRUSTED_ENV_DENYLIST = {
    "APS_TRUSTED_ATTESTATION_KEY",
    "APS_TRUSTED_ATTESTATION_KEY_ID",
    "APS_TRUSTED_REVOKED_KEY_IDS",
    "APS_TRUSTED_ORCHESTRATOR",
    "APS_ORCHESTRATOR_DB",
}
SAFE_ENV_KEYS = {
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE",
    "VIRTUAL_ENV", "SSL_CERT_FILE", "SSL_CERT_DIR",
}
SENSITIVE_PREFIXES = (
    "AWS_", "AZURE_", "GOOGLE_", "GCP_", "GITHUB_", "GH_", "GITLAB_", "CI_JOB_",
    "OPENAI_", "ANTHROPIC_", "HF_", "HUGGINGFACE_", "NPM_TOKEN", "PYPI_", "TWINE_",
    "DOCKER_", "KUBECONFIG", "VAULT_", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY",
)


def git(root: Path, *args: str) -> str:
    proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, *args], cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"GIT_COMMAND_FAILED:{' '.join(args)}:{proc.stderr.strip()}")
    return proc.stdout.strip()


def resolve_commit(root: Path, ref: str) -> str:
    return git(root, "rev-parse", f"{ref}^{{commit}}")


def resolve_tree(root: Path, ref: str) -> str:
    return git(root, "rev-parse", f"{ref}^{{tree}}")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sensitive_key(key: str) -> bool:
    upper = key.upper()
    return upper in TRUSTED_ENV_DENYLIST or any(upper.startswith(prefix) for prefix in SENSITIVE_PREFIXES)


def clean_env(extra: dict[str, str] | None = None, *, process_token: str | None = None) -> dict[str, str]:
    """Return an explicit allowlist environment for untrusted candidate code.

    Trust markers, signing material, orchestrator locations and common cloud/CI
    credentials are never inherited. Unknown variables are not copied.
    """
    env = {key: value for key, value in os.environ.items() if key in SAFE_ENV_KEYS and not _sensitive_key(key)}
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTEST_ADDOPTS": "-p no:cacheprovider",
        "PYTHONHASHSEED": "0",
        "APS_TRUSTED_CONTEXT": "UNTRUSTED_CANDIDATE",
    })
    if process_token:
        env[PROCESS_TOKEN_ENV] = process_token
    if extra:
        for key, value in extra.items():
            if _sensitive_key(key) or key.startswith("APS_TRUSTED_") or key == "APS_ORCHESTRATOR_DB":
                raise RuntimeError(f"CANDIDATE_ENV_SECRET_FORBIDDEN:{key}")
            env[key] = value
    return env


def _token_processes(token: str) -> list[Any]:
    if psutil is None:
        return []
    matches: list[Any] = []
    for process in psutil.process_iter(attrs=["pid"]):
        if process.pid == os.getpid():
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
    _, survivors = psutil.wait_procs(alive, timeout=3)
    return sorted(process.pid for process in survivors if process.is_running())


def _terminate_process_tree(proc: subprocess.Popen[str], token: str) -> list[int]:
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
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return []


def _cleanup_token(token: str) -> list[int]:
    if psutil is None:
        return [-1]
    survivors = _kill_processes(_token_processes(token))
    time.sleep(0.05)
    survivors.extend(process.pid for process in _token_processes(token))
    return sorted(set(survivors))


@contextmanager
def candidate_worktree(repository: Path, head_sha: str) -> Iterator[Path]:
    """Create an independent immutable candidate checkout.

    A linked ``git worktree`` contains a pointer into the host repository's
    writable ``.git/worktrees`` area. That pointer would either break after
    ``pivot_root`` or force the sandbox to expose shared Git metadata. An
    independent no-local clone copies the object database, so the private root
    contains every Git object required by validators without sharing writable
    trusted paths with the host repository.
    """
    repository = repository.resolve()
    temp = Path(tempfile.mkdtemp(prefix="aps_candidate_"))
    worktree = temp / "worktree"
    try:
        proc = subprocess.run(
            [TRUSTED_GIT_EXECUTABLE, "clone", "--quiet", "--no-local", "--no-checkout", str(repository), str(worktree)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"CANDIDATE_CLONE_FAILED:{proc.stderr.strip()}")
        proc = subprocess.run(
            [TRUSTED_GIT_EXECUTABLE, "checkout", "--quiet", "--detach", head_sha],
            cwd=worktree,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"CANDIDATE_CHECKOUT_FAILED:{proc.stderr.strip()}")
        actual_head = resolve_commit(worktree, "HEAD")
        if actual_head != head_sha:
            raise RuntimeError(f"CHECKOUT_DOES_NOT_MATCH_CANDIDATE:expected={head_sha}:actual={actual_head}")
        if git(worktree, "status", "--porcelain"):
            raise RuntimeError("CANDIDATE_WORKTREE_DIRTY_AT_START")
        yield worktree
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def _pytest_counter(output: str, label: str) -> int:
    matches = re.findall(rf"(?<![\w])([0-9]+)\s+{re.escape(label)}(?:\b|$)", output, flags=re.IGNORECASE)
    return sum(int(value) for value in matches[-1:]) if matches else 0


def _node_id(testcase: ET.Element) -> str:
    file_name = testcase.attrib.get("file")
    name = testcase.attrib.get("name", "unknown")
    if file_name:
        return f"{file_name.replace(chr(92), '/')}::{name}"
    class_name = testcase.attrib.get("classname", "unknown").replace(".", "/")
    return f"{class_name}::{name}"


def _junit_summary(path: Path, terminal_output: str = "") -> dict[str, Any]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    testcases = [case for suite in suites for case in suite.findall(".//testcase")]
    total = sum(int(suite.attrib.get("tests", 0)) for suite in suites)
    failures = sum(int(suite.attrib.get("failures", 0)) for suite in suites)
    errors = sum(int(suite.attrib.get("errors", 0)) for suite in suites)
    skipped = sum(int(suite.attrib.get("skipped", 0)) for suite in suites)
    node_ids = sorted(_node_id(case) for case in testcases)
    skipped_nodes: list[dict[str, str]] = []
    for case in testcases:
        skipped_element = case.find("skipped")
        if skipped_element is not None:
            skipped_nodes.append({
                "node_id": _node_id(case),
                "reason": skipped_element.attrib.get("message") or (skipped_element.text or "").strip(),
            })
    xpassed = _pytest_counter(terminal_output, "xpassed")
    return {
        "collected": total,
        "completed": total,
        "accounted": total,
        "passed": total - failures - errors - skipped,
        "failed": failures,
        "errors": errors,
        "skipped": skipped,
        "xpassed": xpassed,
        "unexpected_skipped": skipped,
        "node_ids": node_ids,
        "skipped_nodes": skipped_nodes,
        "selection_digest": sha256_bytes("\n".join(node_ids).encode("utf-8")),
    }


def _validate_skip_allowlist(summary: dict[str, Any], allowlist: list[dict[str, Any]] | None) -> list[str]:
    allowed = {item.get("node_id"): item for item in (allowlist or []) if isinstance(item, dict)}
    unexpected: list[str] = []
    for skipped in summary.get("skipped_nodes", []):
        policy = allowed.get(skipped.get("node_id"))
        if not policy:
            unexpected.append(str(skipped.get("node_id")))
            continue
        required = ("reason_code", "policy_reference", "expiry", "approver", "justification")
        if any(not isinstance(policy.get(key), str) or not policy[key] for key in required):
            unexpected.append(str(skipped.get("node_id")))
            continue
        try:
            expiry = time.strptime(policy["expiry"][:10], "%Y-%m-%d")
        except ValueError:
            unexpected.append(str(skipped.get("node_id")))
            continue
        if time.mktime(expiry) < time.mktime(time.gmtime()):
            unexpected.append(str(skipped.get("node_id")))
    summary["unexpected_skipped"] = len(unexpected)
    summary["unexpected_skipped_node_ids"] = sorted(unexpected)
    return unexpected


def _rewrite_candidate_paths(command: list[str], root: Path) -> list[str]:
    root_text = str(root.resolve())
    rewritten: list[str] = []
    for value in command:
        if value == root_text:
            rewritten.append("/workspace")
        elif value.startswith(root_text + os.sep):
            rewritten.append("/workspace/" + value[len(root_text) + 1:].replace(os.sep, "/"))
        else:
            rewritten.append(value)
    return rewritten



def _prepare_candidate_execution(
    root: Path,
    argv: list[str],
    *,
    check_id: str,
    test_role: str | None,
    deny_paths: list[str] | None,
    require_sandbox: bool,
    readonly_paths: list[str] | None,
) -> tuple[list[str], list[str], Path | None, tempfile.TemporaryDirectory[str] | None, str, list[str], bool]:
    approved_command = list(argv)
    command = list(argv)
    if command and command[0] in {"python", "python3"}:
        command[0] = sys.executable
        approved_command[0] = sys.executable
    junit_path: Path | None = None
    junit_temp: tempfile.TemporaryDirectory[str] | None = None
    if test_role:
        if "pytest" not in command:
            raise RuntimeError(f"TRUSTED_TEST_COMMAND_NOT_PYTEST:{check_id}")
        junit_temp = tempfile.TemporaryDirectory(prefix="aps_junit_")
        junit_path = Path(junit_temp.name) / "report.xml"
        command.append(f"--junitxml={junit_path}")
    denied = [str(Path(path).resolve()) for path in (deny_paths or [])]
    readonly = sorted(
        {str(Path(path).resolve()) for path in (readonly_paths or [])}
        | {str(Path(sys.executable).resolve().parent.parent)}
    )
    sandbox_mode = "process-isolation-development-only"
    sandbox_adapter_available = False
    if platform.system() == "Linux" and shutil.which("unshare"):
        wrapper = Path(__file__).resolve().parent / "candidate_sandbox.py"
        sandbox = [
            "unshare", "-Urmpn", "--fork", sys.executable, str(wrapper),
            "--workspace", str(root), "--workdir", "/workspace",
        ]
        for path in readonly:
            sandbox.extend(["--readonly-path", path])
        if junit_temp is not None:
            sandbox.extend(["--writable-path", junit_temp.name])
        sandbox.extend(["--", *_rewrite_candidate_paths(command, root)])
        command = sandbox
        sandbox_mode = "linux-private-root-pivot-capdrop-v3"
        sandbox_adapter_available = True
    elif require_sandbox:
        raise RuntimeError("CERTIFIED_SANDBOX_REQUIRED")
    return (
        approved_command, command, junit_path, junit_temp,
        sandbox_mode, denied, sandbox_adapter_available,
    )


def _execute_candidate_process(
    root: Path,
    command: list[str],
    *,
    head_sha: str,
    timeout_seconds: int,
    extra_env: dict[str, str] | None,
) -> dict[str, Any]:
    token = uuid.uuid4().hex
    started = time.monotonic()
    runtime_env = dict(extra_env or {})
    runtime_env.update({"TMPDIR": "/tmp", "TEMP": "/tmp", "TMP": "/tmp"})
    kwargs: dict[str, Any] = {
        "cwd": root,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "env": clean_env(runtime_env, process_token=token),
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(command, **kwargs)
    timed_out = False
    try:
        stdout_text, stderr_text = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(proc, token)
        stdout_text, stderr_text = proc.communicate(timeout=5)
    survivors = _cleanup_token(token)
    current_head = resolve_commit(root, "HEAD")
    dirty = git(root, "status", "--porcelain")
    findings: list[str] = []
    if timed_out:
        findings.append("CANDIDATE_CHECK_TIMEOUT")
    if survivors:
        findings.append(f"CANDIDATE_PROCESS_CLEANUP_FAILED:{survivors}")
    if current_head != head_sha:
        findings.append("CANDIDATE_SHA_CHANGED_DURING_CHECK")
    if dirty:
        findings.append("CANDIDATE_WORKTREE_MUTATED_DURING_CHECK")
    exit_code = 124 if timed_out else int(proc.returncode or 0)
    if exit_code == 126 and "SANDBOX_" in stderr_text:
        findings.append("CERTIFIED_SANDBOX_SETUP_FAILED")
    return {
        "stdout_text": stdout_text,
        "stderr_text": stderr_text,
        "current_head": current_head,
        "exit_code": exit_code,
        "findings": findings,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def _strict_test_findings(
    summary: dict[str, Any],
    *,
    expected_node_ids: list[str] | None,
    minimum_test_count: int | None,
) -> list[str]:
    findings: list[str] = []
    if summary["collected"] <= 0:
        findings.append("TRUSTED_TEST_ZERO_COLLECTED")
    if summary["completed"] != summary["collected"] or summary["accounted"] != summary["collected"]:
        findings.append("TRUSTED_TEST_ACCOUNTING_FAILED")
    if summary["passed"] <= 0:
        findings.append("TRUSTED_TEST_ZERO_PASSED")
    if summary["failed"] or summary["errors"]:
        findings.append("TRUSTED_TEST_FAILURES_PRESENT")
    if summary["xpassed"]:
        findings.append("TRUSTED_TEST_XPASS_PRESENT")
    if summary["unexpected_skipped"]:
        findings.append("TRUSTED_TEST_UNEXPECTED_SKIP")
    expected = sorted(expected_node_ids or [])
    if expected and sorted(summary.get("node_ids", [])) != expected:
        findings.append("TRUSTED_TEST_NODE_SELECTION_DRIFT")
    if minimum_test_count is not None and summary["collected"] < minimum_test_count:
        findings.append("TRUSTED_TEST_COUNT_REDUCTION")
    return findings


def _attach_test_evidence(
    result: dict[str, Any],
    *,
    junit_path: Path | None,
    stdout_text: str,
    stderr_text: str,
    test_role: str,
    skip_allowlist: list[dict[str, Any]] | None,
    expected_node_ids: list[str] | None,
    minimum_test_count: int | None,
) -> None:
    result["test_role"] = test_role
    if junit_path is None or not junit_path.exists():
        result["status"] = "FAIL"
        result["findings"].append("TRUSTED_TEST_REPORT_MISSING")
        return
    report_bytes = junit_path.read_bytes()
    summary = _junit_summary(junit_path, stdout_text + "\n" + stderr_text)
    result["test_summary"] = summary
    result["report_sha256"] = sha256_bytes(report_bytes)
    result["report_content_base64"] = base64.b64encode(report_bytes).decode("ascii")
    _validate_skip_allowlist(summary, skip_allowlist)
    strict_failures = _strict_test_findings(
        summary,
        expected_node_ids=expected_node_ids,
        minimum_test_count=minimum_test_count,
    )
    if strict_failures:
        result["status"] = "FAIL"
        result["findings"].extend(strict_failures)


def run_command(
    root: Path,
    argv: list[str],
    *,
    check_id: str,
    head_sha: str,
    timeout_seconds: int = 600,
    extra_env: dict[str, str] | None = None,
    test_role: str | None = None,
    deny_paths: list[str] | None = None,
    require_sandbox: bool = False,
    readonly_paths: list[str] | None = None,
    expected_node_ids: list[str] | None = None,
    minimum_test_count: int | None = None,
    check_registry_digest: str | None = None,
    check_registry_version: str | None = None,
    skip_allowlist: list[dict[str, Any]] | None = None,
    production_profile_id: str | None = None,
) -> dict[str, Any]:
    if psutil is None:
        raise RuntimeError("CANDIDATE_RUNNER_DEPENDENCY_MISSING:psutil")
    if production_profile_id is None:
        production_profile_id = os.environ.get("APS_EXECUTION_PROFILE_ID") or None
    root = root.resolve()
    (
        approved_command, command, junit_path, junit_temp,
        sandbox_mode, denied, sandbox_adapter_available,
    ) = _prepare_candidate_execution(
        root, argv, check_id=check_id, test_role=test_role,
        deny_paths=deny_paths, require_sandbox=require_sandbox,
        readonly_paths=readonly_paths,
    )
    execution = _execute_candidate_process(
        root, command, head_sha=head_sha,
        timeout_seconds=timeout_seconds, extra_env=extra_env,
    )
    stdout_text = execution["stdout_text"]
    stderr_text = execution["stderr_text"]
    stdout = stdout_text.encode("utf-8", errors="replace")
    stderr = stderr_text.encode("utf-8", errors="replace")
    command_digest = sha256_bytes(
        json.dumps(approved_command, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    sandbox_state = certification_state(root, production_profile_id=production_profile_id)
    sandbox_state["sandbox_adapter_available"] = sandbox_adapter_available
    sandbox_state["sandbox_conformance_passed"] = sandbox_adapter_available and execution["exit_code"] == 0 \
        and not any(item.startswith("CERTIFIED_SANDBOX_SETUP_FAILED") for item in execution["findings"])
    result: dict[str, Any] = {
        "check_id": check_id,
        "command": approved_command,
        "executed_command": command,
        "command_digest": command_digest,
        "working_tree_commit_sha": execution["current_head"],
        "working_tree_tree_sha": resolve_tree(root, "HEAD"),
        "expected_commit_sha": head_sha,
        "exit_code": execution["exit_code"],
        "duration_seconds": execution["duration_seconds"],
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "status": "PASS" if execution["exit_code"] == 0 and not execution["findings"] else "FAIL",
        "findings": execution["findings"],
        "stdout": stdout_text,
        "stderr": stderr_text,
        "environment_policy": "candidate-allowlist-v2",
        "sandbox_mode": sandbox_mode,
        "sandbox_certified": sandbox_state["sandbox_production_certified"],
        **sandbox_state,
        "denied_host_paths_absent": denied,
        "check_registry_digest": check_registry_digest,
        "check_registry_version": check_registry_version,
        "expected_node_ids": sorted(expected_node_ids or []),
        "minimum_test_count": minimum_test_count,
        "skip_allowlist": skip_allowlist or [],
    }
    if test_role:
        _attach_test_evidence(
            result, junit_path=junit_path, stdout_text=stdout_text,
            stderr_text=stderr_text, test_role=test_role,
            skip_allowlist=skip_allowlist, expected_node_ids=expected_node_ids,
            minimum_test_count=minimum_test_count,
        )
    if junit_temp is not None:
        junit_temp.cleanup()
    return result


def evidence_digest(evidence: list[dict[str, Any]]) -> str:
    portable = [{key: value for key, value in item.items() if key not in {"stdout", "stderr"}} for item in evidence]
    return sha256_bytes(json.dumps(portable, sort_keys=True, separators=(",", ":")).encode())
