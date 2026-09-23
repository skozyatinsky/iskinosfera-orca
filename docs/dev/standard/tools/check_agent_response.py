#!/usr/bin/env python3
"""Проверяет готовый ответ агента до отправки пользователю.

Режим ``--codex-stop`` читает событие Codex Stop из стандартного ввода и
всегда печатает валидный JSON. Обычный режим проверяет ``--file``, ``--text``
или текст из стандартного ввода и возвращает привычный код процесса.

Модуль намеренно использует только стандартную библиотеку Python. Правила и
точные исключения берутся из ``agent_response_policy.json``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Sequence, TextIO, TypeVar

try:
    from rule_traceability_types import emits_diagnostic, enforces_rule
except ImportError:  # pragma: no cover - самостоятельный запуск одного файла
    F = TypeVar("F", bound=Callable[..., Any])

    def enforces_rule(_rule_id: str) -> Callable[[F], F]:
        return lambda function: function

    def emits_diagnostic(_rule_id: str, _code: str) -> Callable[[F], F]:
        return lambda function: function


DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "templates" / "agent_response_policy.json"
)
SAFE_FAILURE_MESSAGE = (
    "Ответ не отправлен: программная проверка не пройдена. "
    "Нужна ручная проверка."
)

CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")
LATIN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z'-]{1,}(?![A-Za-z0-9_])"
)
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
# URL может содержать круглые скобки в пути или строке запроса. Маскируем
# адрес целиком, а не только его часть до первой скобки: слова внутри адреса
# являются машинным текстом, но такое же слово рядом остаётся обычной прозой.
URL_RE = re.compile(r"https?://[^\s<>`\"']+", re.IGNORECASE)
MARKDOWN_TARGET_RE = re.compile(r"\]\((?P<target>[^)]+)\)")
WINDOWS_PATH_RE = re.compile(r"(?<!\w)[A-Za-z]:\\[^\s\]\[()<>]+")
POSIX_PATH_RE = re.compile(
    r"(?<![\w])(?:/|\./|\.\./)?"
    r"(?:[A-Za-z0-9_.А-Яа-яЁё-]+/)+[A-Za-z0-9_.А-Яа-яЁё-]+"
)
CLI_OPTION_RE = re.compile(r"(?<!\w)--[A-Za-z0-9][A-Za-z0-9_-]*")
ENV_NAME_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Z][A-Z0-9_]{2,}(?![A-Za-z0-9_])")
INLINE_CODE_RE = re.compile(r"(?<!`)`(?P<value>[^`\n]+)`(?!`)")
EXPLAINED_TERM_RE = re.compile(
    r"(?P<tick>`?)"
    r"(?P<term>(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9+#.:-]*"
    r"(?:[ \t]+[A-Za-z][A-Za-z0-9+#.:-]*){0,5})"
    r"(?P=tick)[ \t]*"
    r"\((?P<translation>[^()\n]*[А-Яа-яЁё][^()\n]*)\)"
)
MACHINE_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.:/\\-]*")

REQUIRED_REPLACEMENTS = {
    "evidence": "доказательства",
    "reachability": "фактическая доступность",
    "runtime inventory": "перечень реально запущенных компонентов",
    "candidate": "проверяемая версия",
}


class PolicyError(ValueError):
    """Политика отсутствует, повреждена или не соответствует контракту."""


class InputError(ValueError):
    """Вход проверки не соответствует выбранному режиму."""


@dataclass(frozen=True)
class ResponsePolicy:
    schema_version: str
    standard_version: str
    language_profile: str
    mixed_language_mode: str
    max_diagnostics: int
    required_translations: dict[str, str]
    products_and_standards: tuple[str, ...]
    technical_terms: tuple[str, ...]
    commands: tuple[str, ...]
    fields: tuple[str, ...]
    code_fence_languages: tuple[str, ...]
    file_suffixes: tuple[str, ...]


@dataclass(frozen=True)
class ResponseViolation:
    code: str
    term: str
    replacement: str
    line: int
    column: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "term": self.term,
            "replacement": self.replacement,
            "line": self.line,
            "column": self.column,
        }


@dataclass(frozen=True)
class ResponseCheckResult:
    status: str
    diagnostic_code: str
    language_profile: str
    violations: tuple[ResponseViolation, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status == "PASS"

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "diagnostic_code": self.diagnostic_code,
            "language_profile": self.language_profile,
            "violations": [item.as_dict() for item in self.violations],
        }


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _read_json_strict(raw: str) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=_strict_object,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON value: {value}")
        ),
    )


def _string_list(container: dict[str, Any], key: str) -> tuple[str, ...]:
    value = container.get(key)
    if not isinstance(value, list) or not value:
        raise PolicyError(f"exemptions.{key} must be a non-empty array")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise PolicyError(f"exemptions.{key} must contain non-empty strings")
    normalized = [item.casefold() for item in value]
    if len(normalized) != len(set(normalized)):
        raise PolicyError(f"exemptions.{key} contains duplicates")
    return tuple(value)


def _validate_policy_data(data: Any) -> ResponsePolicy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be an object")
    required = {
        "schema_version",
        "standard_version",
        "language_profile",
        "mixed_language_mode",
        "failure_mode",
        "max_diagnostics",
        "required_translations",
        "exemptions",
    }
    if set(data) != required:
        raise PolicyError("policy has missing or unknown top-level fields")
    if data["schema_version"] != "1.0.0" or data["standard_version"] != "3.0.0":
        raise PolicyError("unsupported policy or standard version")
    if data["language_profile"] not in {"ru_internal", "en_public", "mixed"}:
        raise PolicyError("unsupported language_profile")
    if data["mixed_language_mode"] not in {"auto", "ru", "en"}:
        raise PolicyError("unsupported mixed_language_mode")
    if data["failure_mode"] != "block":
        raise PolicyError("failure_mode must be block")
    limit = data["max_diagnostics"]
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        raise PolicyError("max_diagnostics must be an integer from 1 to 100")
    translations = data["required_translations"]
    if not isinstance(translations, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) or not value.strip()
        for key, value in translations.items()
    ):
        raise PolicyError("required_translations must map strings to strings")
    for term, replacement_text in REQUIRED_REPLACEMENTS.items():
        if translations.get(term) != replacement_text:
            raise PolicyError(f"required translation is missing or changed: {term}")
    exemptions = data["exemptions"]
    exemption_keys = {
        "products_and_standards",
        "technical_terms",
        "commands",
        "fields",
        "code_fence_languages",
        "file_suffixes",
    }
    if not isinstance(exemptions, dict) or set(exemptions) != exemption_keys:
        raise PolicyError("exemptions has missing or unknown fields")
    policy = ResponsePolicy(
        schema_version=data["schema_version"],
        standard_version=data["standard_version"],
        language_profile=data["language_profile"],
        mixed_language_mode=data["mixed_language_mode"],
        max_diagnostics=limit,
        required_translations=dict(translations),
        products_and_standards=_string_list(exemptions, "products_and_standards"),
        technical_terms=_string_list(exemptions, "technical_terms"),
        commands=_string_list(exemptions, "commands"),
        fields=_string_list(exemptions, "fields"),
        code_fence_languages=_string_list(exemptions, "code_fence_languages"),
        file_suffixes=_string_list(exemptions, "file_suffixes"),
    )
    if any(not re.fullmatch(r"\.[A-Za-z0-9]+", item) for item in policy.file_suffixes):
        raise PolicyError("file_suffixes contains an invalid suffix")
    return policy


def load_policy(path: Path) -> ResponsePolicy:
    """Загружает и проверяет политику без внешней библиотеки JSON Schema."""
    try:
        raw = path.read_bytes().decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise PolicyError(f"cannot read policy: {path}") from exc
    try:
        data = _read_json_strict(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        raise PolicyError("policy is not strict JSON") from exc
    return _validate_policy_data(data)


def _mark(mask: list[bool], start: int, end: int) -> None:
    for index in range(max(start, 0), min(end, len(mask))):
        mask[index] = True


def _mark_matches(mask: list[bool], expression: re.Pattern[str], text: str) -> None:
    for match in expression.finditer(text):
        _mark(mask, match.start(), match.end())


def _exact_expression(value: str) -> re.Pattern[str]:
    escaped = re.escape(value).replace(r"\ ", r"[ \t\r\n]+")
    return re.compile(
        rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])",
        re.IGNORECASE,
    )


def _is_path_or_file(value: str, policy: ResponsePolicy) -> bool:
    stripped = value.strip().strip("<>")
    if URL_RE.fullmatch(stripped) or WINDOWS_PATH_RE.fullmatch(stripped):
        return True
    if POSIX_PATH_RE.fullmatch(stripped):
        return True
    lowered = stripped.casefold()
    return any(lowered.endswith(suffix.casefold()) for suffix in policy.file_suffixes)


def _is_command(value: str, policy: ResponsePolicy) -> bool:
    stripped = value.strip().lstrip("$>").strip()
    if not stripped:
        return False
    first = stripped.split(maxsplit=1)[0].casefold()
    commands = {item.casefold() for item in policy.commands}
    return first in commands


def _is_known_exact(value: str, policy: ResponsePolicy) -> bool:
    known = {
        *(item.casefold() for item in policy.products_and_standards),
        *(item.casefold() for item in policy.technical_terms),
        *(item.casefold() for item in policy.fields),
    }
    return value.strip().casefold() in known


def _is_machine_inline(value: str, policy: ResponsePolicy) -> bool:
    stripped = value.strip()
    if _is_path_or_file(stripped, policy) or _is_command(stripped, policy):
        return True
    if _is_known_exact(stripped, policy):
        return True
    if stripped.endswith("[]") and _is_known_exact(stripped[:-2], policy):
        return True
    if re.fullmatch(
        r"--[A-Za-z0-9][A-Za-z0-9_-]*(?:[ =][A-Za-z_][A-Za-z0-9_-]*)?",
        stripped,
    ):
        return True
    if stripped in {"True", "False", "None", "true", "false", "null"}:
        return True
    if not MACHINE_IDENTIFIER_RE.fullmatch(stripped):
        return False
    return (
        "_" in stripped
        or "." in stripped
        or ":" in stripped
        or "/" in stripped
        or "\\" in stripped
        or any(character.isdigit() for character in stripped)
        or (stripped.isupper() and len(stripped) > 1)
        or any(character.isupper() for character in stripped[1:])
    )


def _looks_like_code(body: str, language: str, policy: ResponsePolicy) -> bool:
    if language.casefold() not in {
        item.casefold() for item in policy.code_fence_languages
    }:
        return False
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if not lines:
        return False
    code_re = re.compile(
        r"^(?:def |class |from |import |const |let |function |SELECT\s|"
        r"\{|\[|[A-Za-z_$][A-Za-z0-9_$.-]*\s*=)|[{}();=]|--[A-Za-z]"
    )
    return any(_is_command(line, policy) or code_re.search(line) for line in lines)


def _mark_fenced_code(text: str, mask: list[bool], policy: ResponsePolicy) -> None:
    lines = text.splitlines(keepends=True)
    offset = 0
    opened: tuple[str, str, int, int] | None = None
    for line in lines:
        stripped = line.lstrip()
        line_start = offset
        line_end = offset + len(line)
        if opened is None:
            match = re.match(r"(?P<fence>`{3,}|~{3,})(?P<info>[^\n]*)", stripped)
            if match:
                info_parts = match.group("info").strip().split(maxsplit=1)
                opened = (
                    match.group("fence")[0],
                    info_parts[0] if info_parts else "",
                    line_start,
                    line_end,
                )
                _mark(mask, line_start, line_end)
        else:
            fence_char, language, block_start, body_start = opened
            if re.match(rf"{re.escape(fence_char)}{{3,}}\s*$", stripped.rstrip("\r\n")):
                body = text[body_start:line_start]
                if _looks_like_code(body, language, policy):
                    _mark(mask, block_start, line_end)
                else:
                    _mark(mask, line_start, line_end)
                opened = None
        offset = line_end


def _build_verified_mask(text: str, policy: ResponsePolicy) -> list[bool]:
    mask = [False] * len(text)
    for expression in (HTML_COMMENT_RE, URL_RE, WINDOWS_PATH_RE, POSIX_PATH_RE):
        _mark_matches(mask, expression, text)
    for match in MARKDOWN_TARGET_RE.finditer(text):
        _mark(mask, match.start("target"), match.end("target"))
    suffixes = "|".join(re.escape(item) for item in policy.file_suffixes)
    filename_re = re.compile(
        rf"(?<![\w])[-A-Za-z0-9_.А-Яа-яЁё]+(?:{suffixes})(?![\w])",
        re.IGNORECASE,
    )
    for expression in (filename_re, CLI_OPTION_RE, ENV_NAME_RE):
        _mark_matches(mask, expression, text)
    _mark_fenced_code(text, mask, policy)
    for match in INLINE_CODE_RE.finditer(text):
        if _is_machine_inline(match.group("value"), policy):
            _mark(mask, match.start(), match.end())
        else:
            _mark(mask, match.start(), match.start("value"))
            _mark(mask, match.end("value"), match.end())
    for match in EXPLAINED_TERM_RE.finditer(text):
        _mark(mask, match.start(), match.end())
    exact_values = (
        *policy.products_and_standards,
        *policy.technical_terms,
        *policy.commands,
    )
    for value in sorted(exact_values, key=len, reverse=True):
        _mark_matches(mask, _exact_expression(value), text)
    for field in policy.fields:
        field_re = re.compile(
            rf"(?P<quote>['\"]){re.escape(field)}(?P=quote)\s*[:=]",
            re.IGNORECASE,
        )
        for match in field_re.finditer(text):
            _mark(mask, match.start(), match.end())
    return mask


def _location(text: str, position: int) -> tuple[int, int]:
    line = text.count("\n", 0, position) + 1
    previous_line = text.rfind("\n", 0, position)
    return line, position - previous_line


def _is_protected(mask: Sequence[bool], start: int, end: int) -> bool:
    return any(mask[index] for index in range(start, end))


def _english_violations(
    text: str, policy: ResponsePolicy
) -> tuple[ResponseViolation, ...]:
    mask = _build_verified_mask(text, policy)
    violations: list[ResponseViolation] = []
    for term, replacement_text in sorted(
        policy.required_translations.items(), key=lambda item: len(item[0]), reverse=True
    ):
        for match in _exact_expression(term).finditer(text):
            if _is_protected(mask, match.start(), match.end()):
                continue
            line, column = _location(text, match.start())
            violations.append(ResponseViolation(
                "AGENT_RESPONSE_UNEXPLAINED_ENGLISH",
                match.group(0),
                replacement_text,
                line,
                column,
            ))
            _mark(mask, match.start(), match.end())
            if len(violations) >= policy.max_diagnostics:
                return tuple(violations)
    for match in LATIN_TOKEN_RE.finditer(text):
        if _is_protected(mask, match.start(), match.end()):
            continue
        line, column = _location(text, match.start())
        violations.append(ResponseViolation(
            "AGENT_RESPONSE_UNEXPLAINED_ENGLISH",
            match.group(0),
            "замените русским словом или добавьте русский перевод в скобках",
            line,
            column,
        ))
        if len(violations) >= policy.max_diagnostics:
            break
    return tuple(violations)


def _requires_russian_check(text: str, policy: ResponsePolicy) -> bool:
    if policy.language_profile == "ru_internal":
        return True
    if policy.language_profile == "en_public":
        return False
    if policy.mixed_language_mode == "ru":
        return True
    if policy.mixed_language_mode == "en":
        return False
    return CYRILLIC_RE.search(text) is not None


@enforces_rule("APS-CORE-AGENTRESPONSEGATE-3D71-001")
@emits_diagnostic("APS-CORE-AGENTRESPONSEGATE-3D71-001", "AGENT_RESPONSE_GATE_PASS")
@emits_diagnostic("APS-CORE-AGENTRESPONSEGATE-3D71-001", "AGENT_RESPONSE_GATE_BLOCKED")
@enforces_rule("APS-CORE-AGENTRESPONSEGATE-3D71-002")
@emits_diagnostic(
    "APS-CORE-AGENTRESPONSEGATE-3D71-002", "AGENT_RESPONSE_GATE_PASS"
)
@emits_diagnostic(
    "APS-CORE-AGENTRESPONSEGATE-3D71-002",
    "AGENT_RESPONSE_UNEXPLAINED_ENGLISH",
)
def evaluate_response(text: str, policy: ResponsePolicy) -> ResponseCheckResult:
    """Применяет языковой профиль к одному готовому ответу."""
    if not isinstance(text, str):
        raise InputError("response text must be a string")
    if not _requires_russian_check(text, policy):
        return ResponseCheckResult(
            "PASS", "AGENT_RESPONSE_GATE_PASS", policy.language_profile
        )
    violations = _english_violations(text, policy)
    if violations:
        return ResponseCheckResult(
            "BLOCK",
            "AGENT_RESPONSE_GATE_BLOCKED",
            policy.language_profile,
            violations,
        )
    return ResponseCheckResult(
        "PASS", "AGENT_RESPONSE_GATE_PASS", policy.language_profile
    )


def _block(reason: str) -> dict[str, str]:
    return {"decision": "block", "reason": reason}


def _detailed_reason(result: ResponseCheckResult) -> str:
    lines = [
        "AGENT_RESPONSE_GATE_BLOCKED: ответ не прошёл обязательную проверку языка.",
        "Исправьте нарушения:",
    ]
    for item in result.violations:
        lines.append(
            f"- строка {item.line}, столбец {item.column}: "
            f"{item.term!r} → {item.replacement}."
        )
    lines.append("Перепишите только итоговый ответ и снова завершите ход.")
    return "\n".join(lines)


@enforces_rule("APS-CORE-AGENTRESPONSEGATE-3D71-003")
@emits_diagnostic(
    "APS-CORE-AGENTRESPONSEGATE-3D71-003", "AGENT_RESPONSE_STOP_PASS"
)
@emits_diagnostic(
    "APS-CORE-AGENTRESPONSEGATE-3D71-003", "AGENT_RESPONSE_INPUT_INVALID"
)
@emits_diagnostic(
    "APS-CORE-AGENTRESPONSEGATE-3D71-003", "AGENT_RESPONSE_POLICY_INVALID"
)
@emits_diagnostic(
    "APS-CORE-AGENTRESPONSEGATE-3D71-003", "AGENT_RESPONSE_INTERNAL_ERROR"
)
@emits_diagnostic(
    "APS-CORE-AGENTRESPONSEGATE-3D71-003", "AGENT_RESPONSE_REPEAT_BLOCKED"
)
def codex_stop_response(
    raw_event: str,
    policy_path: Path = DEFAULT_POLICY_PATH,
    *,
    language_profile: str | None = None,
    mixed_language_mode: str | None = None,
) -> dict[str, str]:
    """Возвращает только допустимый ответ для Codex Stop, включая ошибки."""
    try:
        policy = load_policy(policy_path)
        if language_profile is not None:
            policy = replace(policy, language_profile=language_profile)
        if mixed_language_mode is not None:
            policy = replace(policy, mixed_language_mode=mixed_language_mode)
        try:
            event = _read_json_strict(raw_event)
        except (json.JSONDecodeError, ValueError) as exc:
            raise InputError("Codex Stop input is not strict JSON") from exc
        if not isinstance(event, dict):
            raise InputError("Codex Stop input must be an object")
        text = event.get("last_assistant_message")
        if not isinstance(text, str):
            raise InputError("last_assistant_message must be a string")
        stop_hook_active = event.get("stop_hook_active", False)
        if not isinstance(stop_hook_active, bool):
            raise InputError("stop_hook_active must be a boolean")
        result = evaluate_response(text, policy)
        if result.passed:
            return {}
        if stop_hook_active:
            return _block(
                "AGENT_RESPONSE_REPEAT_BLOCKED: выведите только это сообщение: "
                f"{SAFE_FAILURE_MESSAGE}"
            )
        return _block(_detailed_reason(result))
    except PolicyError:
        return _block(
            "AGENT_RESPONSE_POLICY_INVALID: политика проверки отсутствует "
            "или повреждена. Ответ не отправлен."
        )
    except InputError:
        return _block(
            "AGENT_RESPONSE_INPUT_INVALID: событие Stop не содержит "
            "обязательный корректный вход. Ответ не отправлен."
        )
    except Exception:
        return _block(
            "AGENT_RESPONSE_INTERNAL_ERROR: проверка завершилась внутренней "
            "ошибкой. Ответ не отправлен."
        )


def _plain_result(result: ResponseCheckResult) -> str:
    if result.passed:
        return "AGENT_RESPONSE_GATE_PASS: ответ соответствует политике."
    lines = ["AGENT_RESPONSE_GATE_BLOCKED: ответ не соответствует политике."]
    for item in result.violations:
        lines.append(
            f"{item.code}:{item.line}:{item.column}: "
            f"{item.term!r} → {item.replacement}"
        )
    return "\n".join(lines)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--file", type=Path)
    source.add_argument("--text")
    parser.add_argument("--codex-stop", action="store_true")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument(
        "--language-profile", choices=["ru_internal", "en_public", "mixed"]
    )
    parser.add_argument("--mixed-language-mode", choices=["auto", "ru", "en"])
    parser.add_argument("--json", action="store_true", dest="json_output")
    return parser.parse_args(argv)


def _read_cli_text(args: argparse.Namespace, stdin: TextIO) -> str:
    if args.text is not None:
        return args.text
    if args.file is not None:
        try:
            return args.file.read_text(encoding="utf-8")
        except OSError as exc:
            raise InputError(f"cannot read response file: {args.file}") from exc
    return stdin.read()


def _run_regular_cli(
    args: argparse.Namespace, stdin: TextIO, stdout: TextIO, stderr: TextIO
) -> int:
    try:
        policy = load_policy(args.policy)
        if args.language_profile is not None:
            policy = replace(policy, language_profile=args.language_profile)
        if args.mixed_language_mode is not None:
            policy = replace(policy, mixed_language_mode=args.mixed_language_mode)
        result = evaluate_response(_read_cli_text(args, stdin), policy)
    except PolicyError:
        print("AGENT_RESPONSE_POLICY_INVALID: политика отсутствует или повреждена.", file=stderr)
        return 2
    except InputError:
        print("AGENT_RESPONSE_INPUT_INVALID: текст ответа недоступен.", file=stderr)
        return 2
    except Exception:
        print("AGENT_RESPONSE_INTERNAL_ERROR: внутренняя ошибка проверки.", file=stderr)
        return 2
    if args.json_output:
        print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True), file=stdout)
    else:
        print(_plain_result(result), file=stdout)
    return 0 if result.passed else 1


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    args = _parse_args(argv)
    if args.codex_stop:
        if args.file is not None or args.text is not None or args.json_output:
            print(json.dumps(_block(
                "AGENT_RESPONSE_INPUT_INVALID: режим --codex-stop нельзя "
                "объединять с --file, --text или --json."
            ), ensure_ascii=False), file=stdout)
            return 0
        response = codex_stop_response(
            stdin.read(),
            args.policy,
            language_profile=args.language_profile,
            mixed_language_mode=args.mixed_language_mode,
        )
        print(json.dumps(response, ensure_ascii=False, sort_keys=True), file=stdout)
        return 0
    return _run_regular_cli(args, stdin, stdout, stderr)


if __name__ == "__main__":
    raise SystemExit(main())
