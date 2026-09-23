#!/usr/bin/env python3
"""Generate a deterministic, self-contained STANDARD_OVERVIEW.html."""
from __future__ import annotations

import argparse
import json
import re
from html import escape
from pathlib import Path


def read(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return default


def strip_md(value: str) -> str:
    value = re.sub(r"`([^`]+)`", r"\1", value)
    value = re.sub(r"\*\*([^*]+)\*\*", r"\1", value)
    value = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", value)
    return value.strip()


def inline_md(value: str) -> str:
    placeholders: list[str] = []

    def hold(html: str) -> str:
        placeholders.append(html)
        return f"@@H{len(placeholders)-1}@@"

    out = escape(value.strip())

    def link_sub(match: re.Match[str]) -> str:
        label, href = match.group(1), match.group(2)
        attrs = ' target="_blank" rel="noopener noreferrer"' if href.startswith(("http://", "https://")) else ""
        return hold(f'<a href="{escape(href, quote=True)}"{attrs}>{label}</a>')

    out = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link_sub, out)
    out = re.sub(r"`([^`]+)`", lambda m: hold(f"<code>{m.group(1)}</code>"), out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    for i, html in enumerate(placeholders):
        out = out.replace(f"@@H{i}@@", html)
    return out


def parse_table(text: str, header_prefix: str, columns: int) -> list[list[str]]:
    rows: list[list[str]] = []
    active = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(header_prefix):
            active = True
            continue
        if not active:
            continue
        if re.match(r"^\|\s*:?-+", line):
            continue
        if not line.startswith("|"):
            if rows:
                break
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < columns:
            continue
        if len(cells) > columns:
            if columns == 3:
                cells = [cells[0], " | ".join(cells[1:-1]), cells[-1]]
            elif columns == 4:
                cells = cells[:3] + [" | ".join(cells[3:])]
        rows.append(cells)
    return rows


def enforcement(flag: str) -> tuple[str, str]:
    low = strip_md(flag).lower()
    machine = "--check-" in low or "--artifact" in low
    guidance = any(x in low for x in ("guidance", "review", "документ", "pilot", "planned", "prompt"))
    if machine and guidance:
        return "hybrid", "Гибридный контроль"
    if machine:
        return "machine", "Машинная проверка"
    if guidance:
        return "guidance", "Документ / review / pilot"
    return "declared", "Заявленный механизм"


def category(name: str, desc: str) -> str:
    value = f"{name} {desc}".lower()
    rules = [
        ("AI и параллельная работа", ("agent", "work package", "worktree", "candidate", "orchestration", "autonomy", "lease")),
        ("Проверка и качество", ("test", "verification", "coverage", "mutation", "quality", "audit", "regression")),
        ("Архитектура", ("module", "architecture", "dependency", "refactor", "layout", "entrypoint")),
        ("Реестры и контракты", ("registry", "contract", "manifest", "snapshot", "schema")),
        ("Безопасность", ("security", "secret", "hardcode", "entitlement", "license")),
        ("Поставка и эксплуатация", ("release", "build", "backup", "sync", "automation")),
        ("Документация и знания", ("documentation", "knowledge", "skill", "communication", "prompt", "overview")),
    ]
    for label, words in rules:
        if any(w in value for w in words):
            return label
    return "Прочее"


def profile_summary(path: Path) -> tuple[str, str]:
    text = read(path)
    title = next((line.lstrip("# ").strip() for line in text.splitlines() if line.startswith("#")), path.stem)
    paragraphs = [
        p.strip().replace("\n", " ")
        for p in text.split("\n\n")
        if p.strip() and not p.lstrip().startswith(("#", ">", "```"))
    ]
    return title, (paragraphs[0][:260] if paragraphs else "Опциональный runtime profile.")


def load_profiles(root: Path) -> list[dict[str, str]]:
    profiles: list[dict[str, str]] = []
    profile_root = root / "profiles"
    if not profile_root.is_dir():
        return profiles
    for path in sorted(profile_root.rglob("*.md")):
        if path.name == "README.md":
            continue
        text = read(path)
        if "EXTERNALIZED / COMPATIBILITY POINTER" in text:
            continue
        title, summary = profile_summary(path)
        profiles.append({
            "path": path.relative_to(root).as_posix(),
            "title": title,
            "summary": summary,
        })
    return profiles


def build(root: Path) -> str:
    manifest = json.loads(read(root / "manifest.json", "{}") or "{}")
    version = str(manifest.get("version", "unknown"))
    release_date = str(manifest.get("release_date", manifest.get("created", "unknown")))
    purpose = str(manifest.get("purpose", "Стандарт управляемой AI-агентной разработки."))

    cap_rows = parse_table(read(root / "CAPABILITIES.md"), "| Слой |", 3)
    caps = []
    categories: dict[str, int] = {}
    counts = {"machine": 0, "hybrid": 0, "guidance": 0, "declared": 0}
    for name, desc, flag in cap_rows:
        key, label = enforcement(flag)
        cat = category(name, desc)
        categories[cat] = categories.get(cat, 0) + 1
        counts[key] += 1
        caps.append({
            "name": strip_md(name),
            "name_html": inline_md(name),
            "desc_html": inline_md(desc),
            "flag_html": inline_md(flag),
            "category": cat,
            "enforcement": key,
            "label": label,
            "search": strip_md(f"{name} {desc} {flag}").lower(),
        })

    prompt_registry = json.loads(read(root / "prompts" / "registry.json", '{"prompts":[]}') or '{"prompts":[]}')
    prompts = prompt_registry.get("prompts", []) if isinstance(prompt_registry, dict) else []
    prompts = [p for p in prompts if isinstance(p, dict)]

    profiles = load_profiles(root)

    influence_rows = parse_table(read(root / "reference" / "INFLUENCE_MAP.md"), "| Ориентир |", 4)

    cap_cards = []
    for item in caps:
        cap_cards.append(
            '<article class="card cap-card" '
            f'data-category="{escape(item["category"], quote=True)}" '
            f'data-enforcement="{item["enforcement"]}" '
            f'data-search="{escape(item["search"], quote=True)}">'
            f'<div class="tags"><span>{escape(item["category"])}</span>'
            f'<span class="{item["enforcement"]}">{escape(item["label"])}</span></div>'
            f'<h3>{item["name_html"]}</h3><p>{item["desc_html"]}</p>'
            f'<div class="control"><strong>Контроль:</strong> {item["flag_html"]}</div></article>'
        )

    prompt_cards = []
    for item in prompts:
        pid = str(item.get("id", "UNKNOWN"))
        path = str(item.get("path", ""))
        search = (pid + " " + str(item.get("title", "")) + " " + str(item.get("mode", "")) + " " + str(item.get("automation_policy", ""))).lower()
        prompt_cards.append(
            f'<article class="card prompt-card" data-search="{escape(search, quote=True)}">'
            f'<div class="tags"><span>{escape(str(item.get("mode", "UNKNOWN")))}</span>'
            f'<span>{escape(str(item.get("automation_policy", "UNKNOWN")))}</span></div>'
            f'<h3><code>{escape(pid)}</code></h3><p>{escape(str(item.get("title", "")))}</p>'
            f'<p><a href="prompts/{escape(path, quote=True)}">Открыть prompt</a></p></article>'
        )

    profile_cards = "".join(
        f'<article class="card"><div class="tags"><span>OPTIONAL PROFILE</span></div>'
        f'<h3>{escape(p["title"])}</h3><p>{escape(p["summary"])}</p>'
        f'<p><a href="{escape(p["path"], quote=True)}">Открыть профиль</a></p></article>'
        for p in profiles
    )
    source_rows = "".join(
        f"<tr><td>{inline_md(r[0])}</td><td>{inline_md(r[1])}</td><td>{inline_md(r[2])}</td><td>{inline_md(r[3])}</td></tr>"
        for r in influence_rows
    )
    category_options = "".join(
        f'<option value="{escape(k, quote=True)}">{escape(k)} ({v})</option>'
        for k, v in sorted(categories.items())
    )
    links = [
        ("Руководство для человека", "STANDARD_GUIDE_FOR_HUMANS.md"),
        ("README", "README.md"),
        ("Capabilities", "CAPABILITIES.md"),
        ("Agent rules", "AGENTS.md"),
        ("Verification Gauntlet", "core/VERIFICATION_GAUNTLET_AND_TOOL_DISCOVERY_STANDARD.md"),
        ("Prompt Catalog", "prompts/README.md"),
        ("Runtime Standard", "core/AGENT_ORCHESTRATION_RUNTIME_STANDARD.md"),
        ("Runtime Profiles", "profiles/README.md"),
        ("Influence Map", "reference/INFLUENCE_MAP.md"),
        ("Known decisions", "DISPOSITION.md"),
        ("Changelog", "CHANGELOG.md"),
    ]
    doc_links = "".join(
        f'<a class="doc" href="{path}"><strong>{escape(label)}</strong><span>{escape(path)}</span></a>'
        for label, path in links
        if (root / path).exists()
    )
    limitations = [
        "Verification profiles и advanced test methods могут быть DOCUMENTED/PILOT до появления project-specific tooling и evidence.",
        "Prompt reports являются семантическим evidence, но не заменяют deterministic validators и CI.",
        "Worktree isolation не является security sandbox; фактический sandbox level должен подтверждаться runtime evidence.",
        "Конкретные runtime profiles и product backlog принадлежат проектам-потребителям; универсальный пакет не является их task tracker.",
        "Autonomous merge разрешается только policy, verification profile и veto gates; AI consensus сам по себе недостаточен.",
    ]

    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="aps-version" content="{escape(version)}"><title>Agent Project Standard v{escape(version)} — обзор</title><style>
:root{{--bg:#f5f7fb;--surface:#fff;--surface2:#eef2f8;--text:#172033;--muted:#5f6d82;--line:#dce3ee;--accent:#2457d6;--green:#087c65;--amber:#9a6200;--shadow:0 12px 32px rgba(24,40,72,.08)}}[data-theme=dark]{{--bg:#0d1420;--surface:#151f2f;--surface2:#1c293d;--text:#edf3ff;--muted:#acb9ce;--line:#2b3a51;--accent:#8cb1ff;--green:#71d5bc;--amber:#efbd68;--shadow:0 14px 36px rgba(0,0,0,.28)}}*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}}a{{color:var(--accent)}}code{{background:var(--surface2);padding:.12em .38em;border-radius:6px}}.container{{width:min(1180px,calc(100% - 28px));margin:auto}}header{{position:sticky;top:0;z-index:20;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}}nav{{display:flex;align-items:center;gap:16px;min-height:62px}}nav a{{text-decoration:none;color:var(--muted);font-size:.9rem}}nav .brand{{font-weight:850;color:var(--text);margin-right:auto}}button,input,select{{font:inherit}}button{{border:1px solid var(--line);background:var(--surface);color:var(--text);border-radius:10px;padding:8px 11px;cursor:pointer}}.hero{{padding:70px 0 32px}}.eyebrow{{font-size:.76rem;text-transform:uppercase;letter-spacing:.13em;font-weight:850;color:var(--accent)}}h1{{font-size:clamp(2.4rem,6vw,5.2rem);line-height:1;letter-spacing:-.055em;margin:12px 0 22px;max-width:1000px}}.lead{{font-size:clamp(1.04rem,2vw,1.32rem);max-width:900px;color:var(--muted)}}.meta,.tags{{display:flex;gap:7px;flex-wrap:wrap}}.meta span,.tags span{{border:1px solid var(--line);background:var(--surface2);border-radius:999px;padding:4px 9px;font-size:.72rem;font-weight:750}}section{{padding:40px 0;scroll-margin-top:72px}}.head{{display:flex;align-items:end;justify-content:space-between;gap:24px;margin-bottom:20px}}.head h2{{font-size:clamp(1.7rem,3vw,2.7rem);letter-spacing:-.035em;margin:0}}.head p{{max-width:650px;color:var(--muted);margin:0}}.grid{{display:grid;gap:15px}}.three{{grid-template-columns:repeat(3,minmax(0,1fr))}}.card{{background:var(--surface);border:1px solid var(--line);border-radius:17px;padding:20px;box-shadow:var(--shadow)}}.card h3{{margin:11px 0 7px}}.card p{{color:var(--muted)}}.benefit strong{{display:block;color:var(--accent);font-size:.78rem}}.flow{{grid-template-columns:repeat(5,minmax(0,1fr))}}.flow .card{{min-height:150px}}.profile.fast{{border-top:4px solid #4888e8}}.profile.assured{{border-top:4px solid #0b9878}}.profile.critical{{border-top:4px solid #d65f49}}.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}}.stat{{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:16px}}.stat strong{{display:block;font-size:1.5rem}}.stat span{{color:var(--muted)}}.controls{{display:grid;grid-template-columns:1.6fr 1fr 1fr auto;gap:10px;margin-bottom:15px}}input,select{{min-height:42px;border:1px solid var(--line);border-radius:9px;padding:8px 11px;background:var(--surface);color:var(--text)}}.cap-grid,.prompt-grid{{grid-template-columns:repeat(3,minmax(0,1fr))}}.cap-card[hidden],.prompt-card[hidden]{{display:none}}.machine{{color:var(--green)!important}}.guidance,.declared{{color:var(--amber)!important}}.control{{border-top:1px solid var(--line);padding-top:10px;font-size:.86rem;word-break:break-word}}.callout{{background:linear-gradient(135deg,color-mix(in srgb,var(--accent) 12%,var(--surface)),var(--surface));border:1px solid var(--line);border-radius:17px;padding:22px;margin-top:15px}}.two{{grid-template-columns:1fr 1fr}}.docs{{display:grid;grid-template-columns:repeat(2,1fr);gap:9px}}.doc{{display:flex;flex-direction:column;text-decoration:none;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:13px}}.doc strong{{color:var(--text)}}.doc span{{font-size:.82rem;color:var(--muted)}}.table-wrap{{overflow:auto;background:var(--surface);border:1px solid var(--line);border-radius:14px}}table{{border-collapse:collapse;width:100%;min-width:900px}}th,td{{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);font-size:.88rem}}th{{background:var(--surface2)}}footer{{border-top:1px solid var(--line);padding:30px 0 45px;color:var(--muted)}}@media(max-width:900px){{.three,.cap-grid,.prompt-grid,.flow,.two{{grid-template-columns:repeat(2,minmax(0,1fr))}}.controls{{grid-template-columns:1fr 1fr}}}}@media(max-width:620px){{nav a:not(.brand){{display:none}}.three,.cap-grid,.prompt-grid,.flow,.two,.docs,.stats,.controls{{grid-template-columns:1fr}}h1{{font-size:2.7rem}}}}@media print{{header,.controls,#theme{{display:none}}.card{{box-shadow:none}}}}
</style></head><body><header><div class="container"><nav><a class="brand" href="#top">Agent Project Standard</a><a href="#benefits">Преимущества</a><a href="#capabilities">Capabilities</a><a href="#prompt-catalog">Промты</a><a href="#runtime-profiles">Runtime</a><button id="theme" type="button">◐</button></nav></div></header><main id="top">
<section class="hero"><div class="container"><div class="eyebrow">Версия {escape(version)} · единый первый экран</div><h1>Управляемая разработка с людьми и AI‑агентами</h1><p class="lead">{escape(purpose)}</p><p class="lead"><strong>Контроль переносится</strong> с попытки вручную прочитать весь AI-generated код на task contracts, scope, validators, независимую проверку и воспроизводимое evidence.</p><div class="meta"><span>Release date: {escape(release_date)}</span><span>Capabilities: {len(caps)}</span><span>Prompts: {len(prompts)}</span><span>Runtime profiles: {len(profiles)}</span></div></div></section>
<section id="benefits"><div class="container"><div class="head"><div><div class="eyebrow">Преимущества</div><h2>Что стандарт даёт</h2></div><p>Не набор советов, а связанная система от требований до выпуска.</p></div><div class="grid three"><article class="card benefit"><strong>01</strong><h3>Управляемые агенты</h3><p>Contracts, branches, worktrees, scopes и evidence.</p></article><article class="card benefit"><strong>02</strong><h3>Машинные правила</h3><p>Schemas и validators отделяют норму от пожелания.</p></article><article class="card benefit"><strong>03</strong><h3>Защита архитектуры</h3><p>Modules, ownership, Dependency Rule и resource leases.</p></article><article class="card benefit"><strong>04</strong><h3>Независимая проверка</h3><p>Cross-review, veto gates и verification profiles.</p></article><article class="card benefit"><strong>05</strong><h3>Воспроизводимый релиз</h3><p>Manifest, version sync, hygiene и ZIP evidence.</p></article><article class="card benefit"><strong>06</strong><h3>Честные ограничения</h3><p>Documented, pilot и enforced не смешиваются.</p></article></div><div class="callout"><strong>Governance Gauntlet</strong> ограничивает полномочия. <strong>Verification Gauntlet</strong> доказывает корректность. <strong>Prompt Catalog</strong> помогает искать смысловые ошибки, которые ещё не формализованы validator.</div></div></section>
<section id="flow"><div class="container"><div class="head"><div><div class="eyebrow">Жизненный цикл</div><h2>Как проходит работа</h2></div></div><div class="grid flow"><article class="card"><h3>1. Требования</h3><p>БТ, неопределённости, approval.</p></article><article class="card"><h3>2. Архитектура</h3><p>ТЗ, interfaces, modules, ownership.</p></article><article class="card"><h3>3. Исполнение</h3><p>Work packages, scopes, branches, leases.</p></article><article class="card"><h3>4. Проверка</h3><p>Tests, review, properties, mutation по риску.</p></article><article class="card"><h3>5. Релиз</h3><p>Integration, rollback и reproducible artifact.</p></article></div></div></section>
<section id="verification-profiles"><div class="container"><div class="head"><div><div class="eyebrow">Verification Gauntlet</div><h2>Строгость по риску</h2></div><p>Implementation agent не понижает профиль собственной задачи.</p></div><div class="grid three"><article class="card profile fast"><h3>FAST</h3><p>Focused tests, affected regression, static и architecture checks.</p></article><article class="card profile assured"><h3>ASSURED</h3><p>Acceptance, integration, coverage, complexity и independent review.</p></article><article class="card profile critical"><h3>CRITICAL</h3><p>Mutation, properties, user-facing QA, security и independent approval.</p></article></div><div class="stats"><div class="stat"><strong>{counts['machine']}</strong><span>машинных capabilities</span></div><div class="stat"><strong>{counts['hybrid']}</strong><span>гибридных</span></div><div class="stat"><strong>{counts['guidance'] + counts['declared']}</strong><span>documented/review/pilot</span></div></div><p><a href="core/VERIFICATION_GAUNTLET_AND_TOOL_DISCOVERY_STANDARD.md">Открыть норматив Verification Gauntlet</a></p></div></section>
<section id="capabilities"><div class="container"><div class="head"><div><div class="eyebrow">Capabilities</div><h2>Что умеет стандарт</h2></div><p>Наличие документа не приравнивается к blocking enforcement.</p></div><div class="controls"><input id="capSearch" type="search" placeholder="Поиск capability"><select id="categoryFilter"><option value="">Все категории</option>{category_options}</select><select id="enforcementFilter"><option value="">Любой контроль</option><option value="machine">Машинный</option><option value="hybrid">Гибридный</option><option value="guidance">Документ/review/pilot</option><option value="declared">Заявленный</option></select><button id="resetCaps" type="button">Сбросить</button></div><div class="grid cap-grid">{''.join(cap_cards)}</div></div></section>
<section id="prompt-catalog"><div class="container"><div class="head"><div><div class="eyebrow">Операционные промты</div><h2>Аудит не даёт автоматического права исправлять</h2></div><p><code>AUDIT_ONLY → approval → REMEDIATION → independent VERIFICATION</code></p></div><div class="callout">Промт полезен для семантического анализа. Validator полезен для deterministic invariant и blocking CI. Они дополняют друг друга.</div><div class="controls"><input id="promptSearch" type="search" placeholder="Prompt ID, mode или назначение"><button id="resetPrompts" type="button">Сбросить</button></div><div class="grid prompt-grid">{''.join(prompt_cards)}</div><p><a href="prompts/README.md">Когда и как запускать промты</a></p></div></section>
<section id="runtime-profiles"><div class="container"><div class="head"><div><div class="eyebrow">Runtime profiles</div><h2>Стандарт не зависит от конкретного ADE</h2></div><p>Универсальное ядро задаёт contract; конкретный profile и backlog хранятся в проекте-потребителе.</p></div><div class="grid three"><article class="card"><h3>Universal core</h3><p>Worktree ≠ sandbox; read scope ≠ write scope; leases, candidates, cross-review, autonomy A0–A4.</p><p><a href="core/AGENT_ORCHESTRATION_RUNTIME_STANDARD.md">Открыть runtime standard</a></p></article>{profile_cards}<article class="card"><h3>Project-owned profile</h3><p>Создаётся по template в integrating project. Product backlog, localization и release pipeline не являются capabilities универсального стандарта.</p><p><a href="templates/RUNTIME_PROFILE_TEMPLATE.md">Открыть template</a></p></article></div></div></section>
<section id="ai-use"><div class="container"><div class="head"><div><div class="eyebrow">Для AI</div><h2>Маршрутизатор контекста</h2></div></div><div class="grid two"><article class="card"><ol><li>Открой overview или source registries.</li><li>Определи capability, enforcement и verification profile.</li><li>Проверь, нужен ли operational prompt.</li><li>Проверь runtime profile и sandbox level.</li><li>Перейди к applicable core/schemas/registries.</li><li>После изменений перегенерируй HTML.</li></ol></article><div class="docs">{doc_links}</div></div></div></section>
<section id="sources"><div class="container"><div class="head"><div><div class="eyebrow">Источники</div><h2>Что заимствовано и адаптировано</h2></div></div><div class="table-wrap"><table><thead><tr><th>Источник</th><th>Берём</th><th>Не копируем</th><th>Где отражено</th></tr></thead><tbody>{source_rows}</tbody></table></div></div></section>
<section id="start"><div class="container"><div class="head"><div><div class="eyebrow">Быстрый старт</div><h2>Порядок внедрения</h2></div></div><div class="grid flow"><article class="card"><h3>1</h3><p>Скопировать core, templates, schemas, tools.</p></article><article class="card"><h3>2</h3><p>Заполнить project context и profile.</p></article><article class="card"><h3>3</h3><p>Зарегистрировать modules, ownership и sources of truth.</p></article><article class="card"><h3>4</h3><p>Запустить validator и golden project.</p></article><article class="card"><h3>5</h3><p>Включить CI и только затем parallel agents.</p></article></div></div></section>
<section id="limits"><div class="container"><div class="head"><div><div class="eyebrow">Ограничения</div><h2>Что ещё не гарантируется</h2></div></div><article class="card"><ul>{''.join(f'<li>{escape(x)}</li>' for x in limitations)}</ul></article></div></section>
</main><footer><div class="container"><strong>Agent Project Standard v{escape(version)}</strong><br>Generated deterministically from manifest, CAPABILITIES, prompt registry, profiles and Influence Map. Release date: {escape(release_date)}.</div></footer><script>
(()=>{{const root=document.documentElement,theme=document.getElementById('theme');const saved=localStorage.getItem('aps-theme');if(saved)root.dataset.theme=saved;theme.addEventListener('click',()=>{{const v=root.dataset.theme==='dark'?'light':'dark';root.dataset.theme=v;localStorage.setItem('aps-theme',v)}});function wire(inputId,resetId,selector,extra){{const input=document.getElementById(inputId),reset=document.getElementById(resetId),cards=[...document.querySelectorAll(selector)];const apply=()=>{{const q=input.value.trim().toLowerCase();for(const c of cards){{let ok=!q||c.dataset.search.includes(q);if(extra)ok=ok&&extra(c);c.hidden=!ok}}}};input.addEventListener('input',apply);reset.addEventListener('click',()=>{{input.value='';apply()}});return apply}}const cat=document.getElementById('categoryFilter'),enf=document.getElementById('enforcementFilter');const capApply=wire('capSearch','resetCaps','.cap-card',c=>(!cat.value||c.dataset.category===cat.value)&&(!enf.value||c.dataset.enforcement===enf.value));cat.addEventListener('change',capApply);enf.addEventListener('change',capApply);wire('promptSearch','resetPrompts','.prompt-card')}})();
</script></body></html>'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="STANDARD_OVERVIEW.html")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    for required in ("manifest.json", "CAPABILITIES.md", "reference/INFLUENCE_MAP.md", "prompts/registry.json"):
        if not (root / required).exists():
            parser.error(f"Missing required source: {required}")
    output.write_text(build(root), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
