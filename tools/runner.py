"""Private, fixed-command tool runner. No host ports, shell, Docker socket or credentials."""
import csv
import io
import json
import ipaddress
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

try:
    from result_rules import profile_records, profiles_to_entities, harvester_records, spiderfoot_records, report_problems
except ModuleNotFoundError:
    from app.result_rules import profile_records, profiles_to_entities, harvester_records, spiderfoot_records, report_problems

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
lock = threading.Lock()
ALLOWED = set(os.getenv("RUNNER_TOOLS", "").split(","))
BINARIES = {"maigret": "/opt/maigret/bin/maigret", "sherlock": "/opt/sherlock/bin/sherlock", "holehe": "/opt/holehe/bin/python", "theharvester": "/opt/harvester-env/bin/theHarvester", "spiderfoot": "/opt/spiderfoot-env/bin/python", "phoneinfoga": "/usr/local/bin/phoneinfoga"}
VERSIONS = {"maigret": "0.6.0", "sherlock": "0.15.0", "holehe": "1.61", "theharvester": "6790b147", "spiderfoot": "4.0", "phoneinfoga": "2.11.0"}
PROBES = {}
BINARIES["pywhat"] = "/opt/pywhat/bin/python"
VERSIONS["pywhat"] = "5.1.0"
BINARIES.update({"socialscan": "/opt/socialscan/bin/socialscan", "ignorant": "/opt/ignorant/bin/python", "whatsmyname": "/usr/local/bin/python"})
VERSIONS.update({"socialscan": "2.0.1", "ignorant": "1.2 + guarded adapter", "whatsmyname": "35576e909ce4 + Chimera checker 1.0"})


@app.on_event("startup")
def probe_commands():
    for id in ALLOWED:
        if id not in BINARIES or not Path(BINARIES[id]).exists():
            continue
        args = [BINARIES[id], "--help"]
        if id == "holehe":
            args = [BINARIES[id], "-c", "import holehe.core; import trio; import httpx"]
        if id == "spiderfoot":
            args = [BINARIES[id], "/opt/spiderfoot/sf.py", "-V"]
        if id == "pywhat":
            args = [BINARIES[id], "-c", "from pywhat import identifier; assert isinstance(identifier.Identifier().identify('example@example.org', only_text=True), dict)"]
        if id == "ignorant":
            args = [BINARIES[id], "-c", "import ignorant.core; import phonenumbers; from ignorant.modules.social_media.instagram import instagram; from ignorant.modules.social_media.snapchat import snapchat; from ignorant.modules.shopping.amazon import amazon"]
        if id == "whatsmyname":
            args = [BINARIES[id], "-c", "import accounts_json; import httpx; import json; from pathlib import Path; assert accounts_json.select_sites(json.loads(Path('/opt/wmn/wmn-data.json').read_text()))"]
        try:
            result = subprocess.run(args, capture_output=True, timeout=25)
            PROBES[id] = {"ok": result.returncode == 0, "version": VERSIONS[id], "message": "Команда запускается" if result.returncode == 0 else result.stderr.decode(errors="replace")[-1200:]}
        except (OSError, subprocess.TimeoutExpired):
            PROBES[id] = {"ok": False, "version": VERSIONS[id], "message": "Команда недоступна или не прошла локальную проверку запуска."}


class Task(BaseModel):
    tool: str
    kind: str
    value: str = Field(min_length=1, max_length=254)


@app.get("/health")
def health():
    available = [id for id in ALLOWED if PROBES.get(id, {}).get("ok")]
    return {"status": "ok", "tools": available, "versions": {id: VERSIONS[id] for id in available}, "diagnostics": PROBES, "message": "Некоторые команды сборщика не прошли локальную проверку запуска." if len(available) < len(ALLOWED) else "Сборщик доступен"}


def command(task, folder):
    binary, value = BINARIES[task.tool], task.value
    if task.tool == "pywhat":
        return [binary, "/opt/runner/pywhat_json.py", value, str(folder / "pywhat.json")]
    if task.tool == "socialscan":
        return [binary, value, "--json", str(folder / "socialscan.json")]
    if task.tool in {"ignorant", "whatsmyname"}:
        return [binary, "/opt/runner/accounts_json.py", task.tool, value, str(folder / (task.tool + ".json"))]
    if task.tool == "maigret":
        return [binary, value, "--json", "simple", "--folderoutput", str(folder), "--top-sites", "100", "--timeout", "8", "--no-recursion", "--no-progressbar"]
    if task.tool == "sherlock":
        return [binary, value, "--csv", "--folderoutput", str(folder), "--timeout", "8", "--no-color", "--print-found"]
    if task.tool == "holehe":
        return [binary, "/opt/runner/holehe_json.py", value, str(folder / "holehe.json")]
    if task.tool == "theharvester":
        return [binary, "-d", value.rsplit("@", 1)[-1], "-b", "crtsh,certspotter", "-l", "100", "-f", str(folder / "harvest")]
    if task.tool == "spiderfoot":
        modules = {"ip": "sfp_whois,sfp_dnsresolve", "domain": "sfp_whois,sfp_dnsresolve,sfp_crt", "email": "sfp_emailformat,sfp_accounts", "phone": "sfp_numverify", "username": "sfp_accounts", "person": "sfp_accounts", "btc": "sfp_blockchain", "evm": "sfp_etherscan", "tron": ""}
        # Modules that require provider keys remain unavailable until quota-aware bridges exist.
        if task.kind in {"phone", "evm", "tron"}:
            return None
        return [binary, "/opt/spiderfoot/sf.py", "-s", value, "-m", modules.get(task.kind, "sfp_accounts"), "-o", "json"]
    if task.tool == "phoneinfoga":
        return [binary, "scan", "-n", value, "--disable", "numverify", "--disable", "ovh"]


def profile_entities(raw):
    return profiles_to_entities(profile_records(raw))


def structured_entities(raw):
    """Extract typed observations from harvester reports and SpiderFoot events."""
    found = {}
    def add(kind, value, relation="упомянут источником", **attrs):
        if not isinstance(value, (str, int)) or not str(value).strip():
            return
        value = str(value).strip()
        found.setdefault((kind, value), {"type": kind, "value": value, "relation": relation, "source_url": value if value.startswith("https://") else "", "attributes": attrs})
    def visit(obj, context=""):
        if isinstance(obj, dict):
            event = str(obj.get("type", obj.get("eventType", ""))).upper().replace(" ", "_").replace("-", "_")
            data = obj.get("data")
            mapping = {"IP_ADDRESS": "ip", "IPV6_ADDRESS": "ip", "DOMAIN_NAME": "domain", "INTERNET_NAME": "domain", "EMAILADDR": "email", "EMAIL_ADDRESS": "email", "USERNAME": "username", "BITCOIN_ADDRESS": "btc", "PHONE_NUMBER": "phone", "BGP_AS_OWNER": "organization", "GEOINFO": "location", "SOCIAL_MEDIA": "profile", "SOCIAL_MEDIA_PRESENCE": "profile", "LINKED_URL_INTERNAL": "url", "LINKED_URL_EXTERNAL": "url"}
            if event in mapping and isinstance(data, str):
                add(mapping[event], data, "наблюдение " + event, module=obj.get("module"), event=event)
            for key, value in obj.items():
                visit(value, str(key).lower())
        elif isinstance(obj, list):
            for item in obj:
                visit(item, context)
        elif isinstance(obj, str):
            if context in {"emails", "email", "email_addresses"} and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", obj):
                add("email", obj)
            elif context in {"hosts", "hostnames", "domains", "host", "hostname"}:
                value = obj.split(":", 1)[0].lstrip("*.")
                if re.fullmatch(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", value):
                    add("domain", value)
            elif context in {"ips", "ip_addresses", "ip"}:
                try:
                    add("ip", str(ipaddress.ip_address(obj)))
                except ValueError:
                    pass
    visit(raw)
    return list(found.values())


@app.post("/run")
def run(task: Task):
    if task.tool not in ALLOWED or task.tool not in BINARIES:
        raise HTTPException(400, "Unknown tool")
    if task.value.startswith("-") or any(ord(c) < 32 for c in task.value):
        raise HTTPException(400, "Invalid target")
    if not lock.acquire(blocking=False):
        return {"error": "runner_busy", "message": "Сборщик занят другим заданием. Повторите позже."}
    try:
        with tempfile.TemporaryDirectory(prefix="chimera-") as tmp:
            folder = Path(tmp)
            args = command(task, folder)
            if args is None:
                return {"error": "requires_configuration", "message": "Для этого типа объекта пока не подключён бесключевой модуль SpiderFoot. Используйте прямой адаптер."}
            with (folder / "stdout.txt").open("w+") as stdout, (folder / "stderr.txt").open("w+") as stderr:
                proc = subprocess.Popen(args, cwd=tmp, stdout=stdout, stderr=stderr, start_new_session=True, env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"})
                timed_out = False
                try:
                    proc.wait(timeout=160)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                stdout.seek(0); stderr.seek(0)
                log = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", stdout.read(1_000_000))
                errorlog = stderr.read(50_000)
            raw = {"tool_version": VERSIONS[task.tool], "stdout": log, "stderr": errorlog, "exit_code": proc.returncode, "timed_out": timed_out, "reports": {}}
            for file in folder.rglob("*"):
                if file.suffix not in {".json", ".jsonl", ".csv"} or file.stat().st_size > 4_000_000:
                    continue
                try:
                    content = file.read_text(encoding="utf-8")
                    raw["reports"][file.name] = json.loads(content) if file.suffix == ".json" else [json.loads(line) for line in content.splitlines() if line.strip()] if file.suffix == ".jsonl" else list(csv.DictReader(io.StringIO(content)))
                except (ValueError, UnicodeError):
                    raw["reports"][file.name] = {"parse_error": True}
            if task.tool == "spiderfoot":
                try:
                    raw["reports"]["events"] = json.loads(log)
                except ValueError:
                    pass
            entities = profile_entities(raw["reports"])
            if task.tool == "theharvester":
                entities = [{"type": r["type"], "value": r["value"], "relation": "находка theHarvester", "source_url": "", "attributes": {}} for r in harvester_records(raw["reports"])]
            elif task.tool == "spiderfoot":
                entities = structured_entities(spiderfoot_records(raw["reports"]))
            notes = ["Исходный вывод сохранён. Совпадение аккаунта не подтверждает владельца."]
            has_errors = bool(re.search(r"\b(ERROR|CRITICAL|FATAL)\b", errorlog)) or report_problems(raw["reports"])
            if has_errors:
                notes.append("Диагностика сборщика содержит ошибки источников; изучите stderr в JSON.")
            if task.tool == "phoneinfoga":
                notes.append("Поисковые ссылки сформированы утилитой и не являются найденными аккаунтами. Страницы по ним не проверялись.")
            if timed_out:
                notes.append("Достигнут предел 160 секунд; сохранены доступные частичные отчёты.")
            if task.tool == "holehe":
                rows = raw["reports"].get("holehe.json", [])
                for item in rows:
                    if item.get("exists") is True and not item.get("rateLimit") and not item.get("error"):
                        domain = item.get("domain")
                        entities.append({"type": "service", "value": item.get("name", "unknown"), "relation": "признак регистрации email", "source_url": "https://" + domain if domain else "", "attributes": item})
                limited = sum(bool(x.get("rateLimit") or x.get("error")) for x in rows)
                if limited:
                    notes.append(f"Модулей с ограничением или ошибкой: {limited}.")
            elif task.tool in {"socialscan", "ignorant", "whatsmyname"}:
                from account_results import normalize
                findings, problems, rows = normalize(task.tool, raw["reports"])
                raw["account_findings"] = findings
                raw["account_checks"] = rows
                limited = len(problems)
                if not rows:
                    return {"error": "source_error", "message": "Сборщик не вернул структурированных проверок.", "raw": raw}
                if limited:
                    notes.append(f"Незавершённых или неоднозначных проверок: {limited}. Они не являются найденными аккаунтами.")
                notes.append("Показаны признаки регистрации или публичные профили. Принадлежность одному человеку требует отдельной проверки.")
                for row in findings:
                    url = row.get("url", "") if task.tool == "whatsmyname" else ""
                    entities.append({"type": "profile" if url else "service", "value": url or row.get("platform", row.get("name", "unknown")), "relation": "возможный аккаунт" if url else "признак регистрации или занятости", "source_url": url, "attributes": {"confirmed_owner": False}})
            else:
                limited = 0
            if proc.returncode != 0 and not raw["reports"]:
                return {"error": "timeout" if timed_out else "source_error", "message": "Сборщик превысил время запуска." if timed_out else "Сборщик не завершил запрос. Проверьте совместимость источника.", "raw": raw}
            return {"raw": raw, "summary": {"Версия": VERSIONS[task.tool], "Найдено связей": len(entities), "Отчётов": len(raw["reports"])}, "entities": entities, "notes": notes, "partial": timed_out or proc.returncode != 0 or bool(limited) or has_errors}
    finally:
        lock.release()
