"""Общие типы и безопасные операции проверок профиля экосистемы."""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any

from rule_traceability_types import RuleFinding

REUSE_RULE = "APS-CORE-ECOSYSTEMREUSE-001"
CONSUMER_RULE = "APS-CORE-CONSUMERSTATUS-001"
HTTP32_RULE = "APS-CORE-HTTP32-001"
AXES_RULE = "APS-CORE-PROJECTAXES-001"
DUAL_INTERFACE_RULE = "APS-CORE-DUALINTERFACE-001"
LOCALIZATION_RULE = "APS-CORE-LOCALIZATION-001"
ACCESSIBILITY_RULE = "APS-CORE-ACCESSIBILITY-001"
PORTABILITY_RULE = "APS-CORE-PORTABILITY-001"
CONTROLLER_RULE = "APS-CORE-CONTROLLERPROFILE-001"
WEB_BOUNDARY_RULE = "APS-CORE-WEBBOUNDARY-001"
INTEGRATION_BOUNDARY_RULE = "APS-CORE-INTEGRATIONBOUNDARIES-001"

DEFAULT_REUSE_PATH = Path("docs/registry/reuse_decisions.json")
DEFAULT_PROFILE_PATH = Path("docs/registry/ecosystem_project_profile.json")
SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
UI_FORMS = {"web_pwa", "desktop_shell", "embedded_ui"}
DUAL_INTERFACE_PURPOSES = {
    "business_workspace",
    "customer_portal",
    "learning_product",
}
REQUIRED_ACCESSIBILITY_CHECKS = {
    "keyboard",
    "visible_focus",
    "accessible_names",
    "contrast",
    "zoom_200",
    "tables",
    "forms",
    "modals",
    "error_messages",
    "not_color_only",
}
KNOWN_OPENAPI_RE = re.compile(r"^(?:2\.0|3\.[01]\.\d+|3\.2\.0)$")
OPENAPI_VERSION_RE = re.compile(
    r"(?mi)^\s*(?:openapi|swagger)\s*:\s*[\"']?(?P<version>[^\s#\"']+)"
)
WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")
def finding(
    code: str,
    rule_id: str,
    message: str,
    *,
    severity: str = "ERROR",
    **evidence: Any,
) -> RuleFinding:
    return RuleFinding(code, rule_id, message, severity, evidence)


def errors_for(findings: list[RuleFinding], rule_id: str) -> list[RuleFinding]:
    return [item for item in findings if item.rule_id == rule_id and item.severity == "ERROR"]


def with_pass(
    findings: list[RuleFinding],
    rule_id: str,
    code: str,
    message: str,
    **evidence: Any,
) -> list[RuleFinding]:
    if not errors_for(findings, rule_id):
        findings.append(finding(code, rule_id, message, severity="INFO", **evidence))
    return findings


def load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_bytes().decode("utf-8-sig")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, str(exc)


def _type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if value is None:
        return "null"
    return type(value).__name__


def schema_errors(
    value: Any,
    schema: dict[str, Any],
    path: str = "$",
    root_schema: dict[str, Any] | None = None,
) -> list[str]:
    """Проверяет используемое пакетами подмножество JSON Schema."""
    root_schema = root_schema or schema
    reference = schema.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/$defs/"):
        target = root_schema.get("$defs", {}).get(reference.rsplit("/", 1)[-1])
        if not isinstance(target, dict):
            return [f"{path}: неразрешимая ссылка схемы {reference!r}"]
        return schema_errors(value, target, path, root_schema)
    errors: list[str] = []
    expected = schema.get("type")
    if expected:
        allowed = expected if isinstance(expected, list) else [expected]
        if _type_name(value) not in allowed:
            return [f"{path}: ожидался тип {expected}, получен {_type_name(value)}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: значение должно быть {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: недопустимое значение {value!r}")
    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            errors.append(f"{path}: строка слишком короткая")
        pattern = schema.get("pattern")
        if pattern and re.search(str(pattern), value) is None:
            errors.append(f"{path}: строка не соответствует {pattern!r}")
    if isinstance(value, list):
        if len(value) < int(schema.get("minItems", 0)):
            errors.append(f"{path}: недостаточно элементов")
        if schema.get("uniqueItems") is True:
            keys = [json.dumps(item, ensure_ascii=False, sort_keys=True) for item in value]
            if len(keys) != len(set(keys)):
                errors.append(f"{path}: элементы должны быть уникальны")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                errors.extend(schema_errors(item, item_schema, f"{path}[{index}]", root_schema))
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: нет обязательного поля {key!r}")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}: лишнее поле {key!r}")
        additional = schema.get("additionalProperties")
        for key, item in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                errors.extend(schema_errors(item, child_schema, f"{path}.{key}", root_schema))
            elif isinstance(additional, dict):
                errors.extend(schema_errors(item, additional, f"{path}.{key}", root_schema))
    return errors


def load_and_check_schema(data: Any, schema_name: str) -> list[str]:
    schema, error = load_json(SCHEMA_DIR / schema_name)
    if error or not isinstance(schema, dict):
        return [f"схема {schema_name} не читается: {error or 'не объект'}"]
    return schema_errors(data, schema)


def is_safe_relative(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    candidate = value.strip().replace("\\", "/")
    if candidate.startswith("/") or WINDOWS_ABSOLUTE_RE.match(candidate):
        return False
    return ".." not in Path(candidate).parts


def absolute_delivery(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if re.search(r"(?:^|\s)(?:-e\s+)?/[A-Za-z0-9_.-]", text):
        return True
    if re.search(r"(?:^|\s)(?:-e\s+)?[A-Za-z]:[\\/]", text):
        return True
    return bool(re.search(r"\bfile:///(?:[A-Za-z]:/|[A-Za-z0-9_.-])", text))


def existing_relative(root: Path, value: Any) -> Path | None:
    if not is_safe_relative(value):
        return None
    path = root / str(value)
    return path if path.is_file() else None


def valid_iso_date(value: Any) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None
