#!/usr/bin/env python3
# ======================================================================
# external_trust.py — версия 1.0
# Общие примитивы внешнего root of trust для signed connector/cert records.
# ======================================================================
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("EXTERNAL_TRUST_CRYPTOGRAPHY_REQUIRED") from exc


class ExternalTrustError(RuntimeError):
    """Fail-closed external trust verification error."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_utc(value: str, finding: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ExternalTrustError(finding) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_registry(env_name: str, missing_finding: str) -> dict[str, dict[str, Any]]:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        raise ExternalTrustError(missing_finding)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExternalTrustError(f"{missing_finding}:INVALID_JSON") from exc
    if not isinstance(data, dict):
        raise ExternalTrustError(f"{missing_finding}:INVALID_SHAPE")
    normalized: dict[str, dict[str, Any]] = {}
    for key_id, entry in data.items():
        if isinstance(key_id, str) and isinstance(entry, str):
            normalized[key_id] = {"public_key": entry}
        elif isinstance(key_id, str) and isinstance(entry, dict):
            normalized[key_id] = dict(entry)
    if not normalized:
        raise ExternalTrustError(f"{missing_finding}:EMPTY")
    return normalized


def revoked_ids(env_name: str) -> set[str]:
    raw = os.environ.get(env_name, "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def load_signed_revocation_state(
    env_name: str,
    *,
    registry_env: str,
    finding_prefix: str,
    forbidden_public_keys: Iterable[str] = (),
    now: datetime | None = None,
) -> set[str]:
    """Загрузить ПОДПИСАННОЕ состояние отзыва с ограничением свежести.

    Неподписанный список ключей бесполезен как контроль: вызывающий просто не
    выставляет переменную, и отсутствие трактуется как «отозванных нет».
    Здесь отсутствие — отказ, а подпись обязана принадлежать ключу, которым
    НЕ подписан проверяемый артефакт: это вынуждает предъявить учётные данные,
    которых у сборщика нет.
    """
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        raise ExternalTrustError(f"{finding_prefix}_REVOCATION_STATE_REQUIRED")
    try:
        record = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExternalTrustError(f"{finding_prefix}_REVOCATION_STATE_INVALID:JSON") from exc
    if not isinstance(record, dict):
        raise ExternalTrustError(f"{finding_prefix}_REVOCATION_STATE_INVALID:SHAPE")

    revoked = record.get("revoked_key_ids")
    if not isinstance(revoked, list) or any(not isinstance(item, str) for item in revoked):
        raise ExternalTrustError(f"{finding_prefix}_REVOCATION_STATE_INVALID:REVOKED_KEY_IDS")

    issued_at = parse_utc(str(record.get("issued_at", "")), f"{finding_prefix}_REVOCATION_STATE_INVALID:ISSUED_AT")
    expires_at = parse_utc(str(record.get("expires_at", "")), f"{finding_prefix}_REVOCATION_STATE_INVALID:EXPIRES_AT")
    moment = now or datetime.now(timezone.utc)
    if issued_at > moment:
        raise ExternalTrustError(f"{finding_prefix}_REVOCATION_STATE_NOT_YET_VALID")
    if expires_at <= moment:
        raise ExternalTrustError(f"{finding_prefix}_REVOCATION_STATE_STALE")

    verify_ed25519_record(
        record,
        registry_env=registry_env,
        revoked_env="",
        missing_registry_finding=f"{finding_prefix}_REVOCATION_REGISTRY_REQUIRED",
        unknown_key_finding=f"{finding_prefix}_REVOCATION_KEY_UNKNOWN",
        revoked_key_finding=f"{finding_prefix}_REVOCATION_KEY_REVOKED",
        signature_finding=f"{finding_prefix}_REVOCATION_SIGNATURE_INVALID",
        denied_public_keys=forbidden_public_keys,
        denied_finding=f"{finding_prefix}_REVOCATION_NOT_INDEPENDENTLY_SIGNED",
    )
    return {item for item in revoked}


def decode_public_key(value: str, finding: str) -> bytes:
    try:
        payload = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ExternalTrustError(finding) from exc
    if len(payload) != 32:
        raise ExternalTrustError(finding)
    return payload


def verify_ed25519_record(
    record: dict[str, Any],
    *,
    registry_env: str,
    revoked_env: str,
    missing_registry_finding: str,
    unknown_key_finding: str,
    revoked_key_finding: str,
    signature_finding: str,
    expected_service_identity: str | None = None,
    expected_deployment_identity: str | None = None,
    denied_public_keys: Iterable[str] = (),
    denied_finding: str | None = None,
) -> dict[str, Any]:
    key_id = record.get("key_id")
    signature_b64 = record.get("signature")
    if not isinstance(key_id, str) or not key_id:
        raise ExternalTrustError(unknown_key_finding)
    if revoked_env and key_id in revoked_ids(revoked_env):
        raise ExternalTrustError(revoked_key_finding)
    registry = load_registry(registry_env, missing_registry_finding)
    entry = registry.get(key_id)
    if not isinstance(entry, dict):
        raise ExternalTrustError(unknown_key_finding)
    if expected_service_identity is not None and entry.get("service_identity") != expected_service_identity:
        raise ExternalTrustError(f"{unknown_key_finding}:SERVICE_IDENTITY")
    if expected_deployment_identity is not None and entry.get("deployment_identity") != expected_deployment_identity:
        raise ExternalTrustError(f"{unknown_key_finding}:DEPLOYMENT_IDENTITY")
    public_key = decode_public_key(str(entry.get("public_key", "")), unknown_key_finding)
    # Ключ, которым подписан сам артефакт, не может быть корнем доверия к нему:
    # иначе сборщик заверяет собственную работу. Сверяем материал ключа, а не
    # его идентификатор — переименование key_id не должно обходить запрет.
    denied = {decode_public_key(str(item), unknown_key_finding) for item in denied_public_keys if item}
    if public_key in denied:
        raise ExternalTrustError(denied_finding or f"{unknown_key_finding}:ARTIFACT_KEY_FORBIDDEN")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ExternalTrustError(signature_finding) from exc
    body = dict(record)
    body.pop("signature", None)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical_bytes(body))
    except (InvalidSignature, ValueError) as exc:
        raise ExternalTrustError(signature_finding) from exc
    return entry
