#!/usr/bin/env python3
# ======================================================================
# prompt_package.py — версия 1.0
# Детерминированная сборка и проверка runtime-specific prompt entrypoints.
# ======================================================================

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Any

from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule

MANIFEST_PATH = Path("prompt_sources/package_manifest.json")
LOCK_PATH = Path("prompt_sources/PROMPT_DEPENDENCY_LOCK.json")
SUPPORTED_RUNTIMES = {"STANDALONE", "CHATGPT_PROJECT", "REPOSITORY_AGENT"}
SUPPORTED_ROLES = {"INDEPENDENT_AUDITOR", "ARCHITECT", "IMPLEMENTER", "RELEASE_VERIFIER"}
SUPPORTED_TARGETS = {"STANDARD_PACKAGE", "EXTERNAL_PROJECT_ADOPTION", "CANDIDATE_RELEASE"}
REQUIRED_ENTRYPOINT_COUNT = 11
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
APS_METADATA_RE = re.compile(r"<!--\s*aps-(?:document|rule|prompt)\b.*?-->", re.IGNORECASE | re.DOTALL)
HEADING_RE = re.compile(r"^(#{1,6})(\s+)", re.MULTILINE)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def load_manifest(root: Path) -> dict[str, Any]:
    return _read_json(root / MANIFEST_PATH)


def load_lock(root: Path) -> dict[str, Any]:
    return _read_json(root / LOCK_PATH)


def component_map(manifest: dict[str, Any]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for item in manifest.get("components", []):
        if not isinstance(item, dict):
            continue
        cid, path = item.get("id"), item.get("path")
        if isinstance(cid, str) and isinstance(path, str):
            out[cid] = {"id": cid, "path": path}
    return out


def _manifest_digest(root: Path) -> str:
    return _sha256_file(root / MANIFEST_PATH)


def build_lock_data(root: Path, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    manifest = manifest or load_manifest(root)
    locked: list[dict[str, str]] = []
    for item in manifest.get("components", []):
        if not isinstance(item, dict):
            continue
        cid, raw_path = item.get("id"), item.get("path")
        if not isinstance(cid, str) or not isinstance(raw_path, str):
            continue
        path = root / raw_path
        locked.append({"id": cid, "path": raw_path, "sha256": _sha256_file(path)})
    return {
        "schema_version": "1.0.0",
        "standard_version": manifest.get("standard_version"),
        "manifest_sha256": _manifest_digest(root),
        "components": sorted(locked, key=lambda item: item["id"]),
    }


def write_lock(root: Path) -> dict[str, Any]:
    data = build_lock_data(root)
    (root / LOCK_PATH).write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return data


def _demote_headings(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        level = min(6, len(match.group(1)) + 2)
        return "#" * level + match.group(2)
    return HEADING_RE.sub(repl, text)


def _component_text(root: Path, raw_path: str) -> str:
    text = (root / raw_path).read_text(encoding="utf-8")
    text = APS_METADATA_RE.sub("", text).strip()
    return _demote_headings(text)


def render_entrypoint(root: Path, entry: dict[str, Any], manifest: dict[str, Any] | None = None) -> str:
    manifest = manifest or load_manifest(root)
    components = component_map(manifest)
    ordered = entry.get("component_ids", [])
    sections: list[str] = []
    for cid in ordered:
        component = components.get(str(cid))
        if component is None:
            raise ValueError(f"unknown component id: {cid}")
        sections.append(f"## Component `{cid}`\n\n{_component_text(root, component['path'])}")
    metadata = "\n".join([
        "<!-- aps-document",
        "type: mixed",
        "-->",
        f"# {entry['title']}",
        "",
        "<!-- aps-rule",
        f"id: {entry['rule_id']}",
        "status: DOCUMENTED",
        "semantic_contract_version: 1",
        "-->",
        "",
        "<!-- aps-prompt",
        f"prompt_id: {entry['prompt_id']}",
        "version: 1.0.0",
        f"mode: {entry['mode']}",
        f"runtime_profile: {entry['runtime_profile']}",
        f"target_kind: {entry['target_kind']}",
        f"role: {entry['role']}",
        "generated: true",
        "-->",
        "",
        "> Generated deterministically from `prompt_sources/package_manifest.json` and the dependency lock. Do not edit directly.",
        "",
        f"Runtime profile: `{entry['runtime_profile']}`  ",
        f"Target: `{entry['target_kind']}`  ",
        f"Role: `{entry['role']}`",
        "",
    ])
    return metadata + "\n\n".join(sections).rstrip() + "\n"


def generate_entrypoints(root: Path) -> list[Path]:
    manifest = load_manifest(root)
    generated: list[Path] = []
    for entry in manifest.get("entrypoints", []):
        if not isinstance(entry, dict):
            continue
        output = root / str(entry["output_path"])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_entrypoint(root, entry, manifest), encoding="utf-8")
        generated.append(output)
    return generated


def _finding(code: str, rule_id: str, message: str, *, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, rule_id, message, severity, evidence)


@enforces_rule("APS-CORE-PROMPTRUNTIMEPROFILE-001")
@emits_diagnostic("APS-CORE-PROMPTRUNTIMEPROFILE-001", "PROMPT_RUNTIME_PROFILE_MATRIX_VALID")
@emits_diagnostic("APS-CORE-PROMPTRUNTIMEPROFILE-001", "PROMPT_RUNTIME_PROFILE_INVALID")
def validate_runtime_profile_matrix(root: Path) -> list[RuleFinding]:
    rule = "APS-CORE-PROMPTRUNTIMEPROFILE-001"
    try:
        manifest = load_manifest(root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("PROMPT_RUNTIME_PROFILE_INVALID", rule, f"manifest unavailable: {exc}")]
    entries = manifest.get("entrypoints")
    if not isinstance(entries, list):
        return [_finding("PROMPT_RUNTIME_PROFILE_INVALID", rule, "entrypoints is not a list")]
    findings: list[RuleFinding] = []
    ids: set[str] = set()
    outputs: set[str] = set()
    runtimes: set[str] = set()
    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            findings.append(_finding("PROMPT_RUNTIME_PROFILE_INVALID", rule, "entrypoint is not an object", index=index))
            continue
        pid = item.get("prompt_id")
        output = item.get("output_path")
        runtime = item.get("runtime_profile")
        role = item.get("role")
        target = item.get("target_kind")
        if not isinstance(pid, str) or pid in ids:
            findings.append(_finding("PROMPT_RUNTIME_PROFILE_INVALID", rule, "duplicate or missing prompt_id", index=index, prompt_id=pid))
        else:
            ids.add(pid)
        if not isinstance(output, str) or output in outputs or not output.startswith("prompts/generated/"):
            findings.append(_finding("PROMPT_RUNTIME_PROFILE_INVALID", rule, "unsafe or duplicate output_path", index=index, output_path=output))
        else:
            outputs.add(output)
        if runtime not in SUPPORTED_RUNTIMES or role not in SUPPORTED_ROLES or target not in SUPPORTED_TARGETS:
            findings.append(_finding("PROMPT_RUNTIME_PROFILE_INVALID", rule, "unsupported runtime/role/target", index=index, runtime=runtime, role=role, target=target))
        if isinstance(runtime, str):
            runtimes.add(runtime)
    if len(entries) != REQUIRED_ENTRYPOINT_COUNT or runtimes != SUPPORTED_RUNTIMES:
        findings.append(_finding("PROMPT_RUNTIME_PROFILE_INVALID", rule, "runtime matrix incomplete", entrypoints=len(entries), runtimes=sorted(runtimes)))
    return findings or [_finding("PROMPT_RUNTIME_PROFILE_MATRIX_VALID", rule, "runtime profile matrix is complete", severity="INFO", entrypoints=len(entries))]


@enforces_rule("APS-CORE-PROMPTRUNTIMEPROFILE-002")
@emits_diagnostic("APS-CORE-PROMPTRUNTIMEPROFILE-002", "PROMPT_PACKAGE_GENERATION_VALID")
@emits_diagnostic("APS-CORE-PROMPTRUNTIMEPROFILE-002", "PROMPT_PACKAGE_GENERATION_DRIFT")
def validate_deterministic_generation(root: Path) -> list[RuleFinding]:
    rule = "APS-CORE-PROMPTRUNTIMEPROFILE-002"
    try:
        manifest = load_manifest(root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("PROMPT_PACKAGE_GENERATION_DRIFT", rule, f"manifest unavailable: {exc}")]
    findings: list[RuleFinding] = []
    for entry in manifest.get("entrypoints", []):
        if not isinstance(entry, dict):
            continue
        output = root / str(entry.get("output_path", ""))
        try:
            expected = render_entrypoint(root, entry, manifest).encode("utf-8")
        except (OSError, KeyError, ValueError) as exc:
            findings.append(_finding("PROMPT_PACKAGE_GENERATION_DRIFT", rule, f"cannot render entrypoint: {exc}", prompt_id=entry.get("prompt_id")))
            continue
        if not output.is_file() or output.read_bytes() != expected:
            findings.append(_finding("PROMPT_PACKAGE_GENERATION_DRIFT", rule, "generated entrypoint differs from canonical components", prompt_id=entry.get("prompt_id"), output_path=str(entry.get("output_path"))))
    return findings or [_finding("PROMPT_PACKAGE_GENERATION_VALID", rule, "all generated entrypoints are deterministic", severity="INFO")]


@enforces_rule("APS-CORE-PROMPTRUNTIMEPROFILE-003")
@emits_diagnostic("APS-CORE-PROMPTRUNTIMEPROFILE-003", "PROMPT_PROJECT_DEPENDENCY_LOCK_VALID")
@emits_diagnostic("APS-CORE-PROMPTRUNTIMEPROFILE-003", "PROMPT_PROJECT_DEPENDENCY_LOCK_INVALID")
def validate_dependency_lock(root: Path) -> list[RuleFinding]:
    rule = "APS-CORE-PROMPTRUNTIMEPROFILE-003"
    try:
        manifest = load_manifest(root)
        actual = load_lock(root)
        expected = build_lock_data(root, manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("PROMPT_PROJECT_DEPENDENCY_LOCK_INVALID", rule, f"dependency lock unavailable: {exc}")]
    findings: list[RuleFinding] = []
    if actual != expected:
        findings.append(_finding("PROMPT_PROJECT_DEPENDENCY_LOCK_INVALID", rule, "dependency lock differs from canonical component hashes"))
    for entry in manifest.get("entrypoints", []):
        if not isinstance(entry, dict) or entry.get("runtime_profile") != "CHATGPT_PROJECT":
            continue
        tokens = set(entry.get("required_identity_tokens", []))
        if entry.get("project_instructions_required") is not True or "PROJECT_INSTRUCTIONS_DIGEST" not in tokens:
            findings.append(_finding("PROMPT_PROJECT_DEPENDENCY_LOCK_INVALID", rule, "ChatGPT Project entrypoint lacks project-instructions digest binding", prompt_id=entry.get("prompt_id")))
    return findings or [_finding("PROMPT_PROJECT_DEPENDENCY_LOCK_VALID", rule, "dependency lock and project-instructions binding are valid", severity="INFO")]


def _noncomment_text(value: str) -> str:
    return HTML_COMMENT_RE.sub("", value)


@enforces_rule("APS-CORE-PROMPTRUNTIMEPROFILE-004")
@emits_diagnostic("APS-CORE-PROMPTRUNTIMEPROFILE-004", "PROMPT_EXACT_IDENTITY_PINNING_VALID")
@emits_diagnostic("APS-CORE-PROMPTRUNTIMEPROFILE-004", "PROMPT_EXACT_IDENTITY_PINNING_MISSING")
def validate_exact_identity_pinning(root: Path) -> list[RuleFinding]:
    rule = "APS-CORE-PROMPTRUNTIMEPROFILE-004"
    try:
        manifest = load_manifest(root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("PROMPT_EXACT_IDENTITY_PINNING_MISSING", rule, f"manifest unavailable: {exc}")]
    findings: list[RuleFinding] = []
    for entry in manifest.get("entrypoints", []):
        if not isinstance(entry, dict):
            continue
        required = entry.get("required_identity_tokens", [])
        output = root / str(entry.get("output_path", ""))
        if not output.is_file():
            findings.append(_finding("PROMPT_EXACT_IDENTITY_PINNING_MISSING", rule, "generated entrypoint missing", prompt_id=entry.get("prompt_id")))
            continue
        text = _noncomment_text(output.read_text(encoding="utf-8"))
        missing = [token for token in required if not isinstance(token, str) or re.search(rf"(?<![A-Z0-9_]){re.escape(token)}(?![A-Z0-9_])", text) is None]
        if missing:
            findings.append(_finding("PROMPT_EXACT_IDENTITY_PINNING_MISSING", rule, "identity token missing outside comments", prompt_id=entry.get("prompt_id"), missing=missing))
    return findings or [_finding("PROMPT_EXACT_IDENTITY_PINNING_VALID", rule, "all entrypoints contain exact identity fields", severity="INFO")]


def validate_package(root: Path) -> list[RuleFinding]:
    """Run every production validator through explicit, statically traceable calls."""
    findings: list[RuleFinding] = []
    findings.extend(validate_runtime_profile_matrix(root))
    findings.extend(validate_deterministic_generation(root))
    findings.extend(validate_dependency_lock(root))
    findings.extend(validate_exact_identity_pinning(root))
    return findings


def build_prompt_archive(root: Path, output: Path) -> dict[str, Any]:
    manifest = load_manifest(root)
    paths = [MANIFEST_PATH, LOCK_PATH, Path("prompt_sources/README.md")]
    paths.extend(Path(str(item["path"])) for item in manifest.get("components", []) if isinstance(item, dict))
    paths.extend(Path(str(item["output_path"])) for item in manifest.get("entrypoints", []) if isinstance(item, dict))
    unique = sorted(set(paths), key=lambda p: p.as_posix())
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel in unique:
            data = (root / rel).read_bytes()
            info = zipfile.ZipInfo(rel.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 & 0xFFFF) << 16
            info.create_system = 3
            zf.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return {"path": str(output), "sha256": _sha256_file(output), "file_count": len(unique)}
