"""Normalize PhoneInfoga's console output without treating search dorks as findings."""
import re
from urllib.parse import parse_qs, urlsplit

VERSION = "1.1"
CATEGORIES = {"Social media": "Социальные сети", "Disposable providers": "Сервисы приёма SMS", "Reputation": "Репутация", "Individuals": "Публичные упоминания", "General": "Общий поиск"}
FIELDS = {"Raw local": "raw_local", "Local": "local", "E164": "e164", "International": "international", "Country": "country_code"}


def parse_console(stdout):
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", stdout)
    scanner, category = "", "Общий поиск"
    fields, searches, scanners, seen = {}, [], [], set()
    for raw_line in clean.splitlines():
        line = raw_line.strip()
        match = re.fullmatch(r"Results for (\S+)", line)
        if match:
            scanner = match.group(1)
            scanners.append(scanner)
            continue
        if scanner == "local":
            key, sep, value = line.partition(":")
            if sep and key in FIELDS and value.strip():
                fields[FIELDS[key]] = value.strip()
        if scanner == "googlesearch":
            if line.endswith(":") and not line.startswith("URL:"):
                category = CATEGORIES.get(line[:-1], line[:-1])
            if not line.startswith("URL:"):
                continue
            url = line[4:].strip()
            try:
                parsed = urlsplit(url)
                if parsed.scheme != "https" or parsed.hostname not in {"www.google.com", "google.com"} or parsed.path != "/search":
                    continue
                query = parse_qs(parsed.query).get("q", [""])[0]
            except ValueError:
                continue
            if not query or url in seen:
                continue
            seen.add(url)
            site = re.search(r"(?:^|\s)site:([\w.-]+)", query)
            searches.append({"url": url, "query": query, "category": category, "site": site.group(1) if site else None, "label": site.group(1) if site else "Документы" if "ext:" in query else "Общий запрос", "visited": False, "confirmed_result": False})
    return {"local": fields, "searches": searches, "scanners": list(dict.fromkeys(scanners)), "account_search_performed": False}


def normalize(result):
    """Preserve original raw output and acquisition time; rebuild derived observations."""
    raw = result.get("raw", {})
    if not isinstance(raw, dict) or not isinstance(raw.get("stdout"), str):
        return result
    parsed = parse_console(raw["stdout"])
    local = parsed["local"]
    entities = []
    if re.fullmatch(r"[A-Z]{2}", local.get("country_code", "")):
        entities.append({"type": "country", "value": local["country_code"], "relation": "страна нумерации", "source_url": "https://github.com/sundowndev/phoneinfoga", "attributes": {"scanner": "local", "current_location": False}})
    summary = {"Версия утилиты": raw.get("tool_version", "неизвестна")}
    for key, label in (("e164", "Номер E.164"), ("local", "Национальный формат"), ("raw_local", "Национальный номер"), ("international", "Международный номер"), ("country_code", "Страна нумерации")):
        if key in local:
            summary[label] = local[key]
    summary.update({"Сканеры с ответом": parsed["scanners"], "Подготовлено поисковых запросов": len(parsed["searches"]), "Проверка аккаунтов": "Не выполнялась"})
    notes = ["Страна относится к плану нумерации и не определяет текущее местоположение телефона.", "Google-запросы подготовлены PhoneInfoga для ручной проверки. Они не подтверждают регистрацию, владельца или наличие номера на перечисленных сайтах."]
    notes += [n for n in result.get("notes", []) if any(word in n.lower() for word in ("ошиб", "огранич", "160 секунд"))]
    partial = bool(result.get("partial"))
    if not local:
        notes.append("Локальные поля номера отсутствуют в выводе PhoneInfoga; сведения о номере не восстановлены.")
        partial = True
    return {**result, "raw": {**raw, "parsed": parsed}, "summary": summary, "entities": entities, "searches": parsed["searches"], "notes": notes, "partial": partial, "normalizer_version": VERSION}
