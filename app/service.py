import hashlib
import json
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from app.catalog import TOOLS, CATALOG, metadata
from app.providers import Providers, ProviderError, validate_target
from app.storage import now


class Engine:
    def __init__(self, store):
        self.store = store
        self.providers = Providers(store)
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="chimera-job")
        self.health = {}
        self.health_lock = threading.Lock()
        self.cache_locks = {id: threading.Lock() for id in CATALOG}
        self.runner_locks = {t.runner: threading.Lock() for t in TOOLS if t.runner}
        self.store.recover()
        self.store.migrate_phoneinfoga()
        self.store.migrate_cases()

    def runner_health(self, env):
        url = os.getenv(env, "")
        if not url:
            return {"tools": [], "message": "Запустите контейнеры сборщиков (профиль tools)."}
        with self.health_lock:
            cached = self.health.get(env)
            if cached and time.monotonic() - cached[0] < 15:
                return cached[1]
            try:
                r = httpx.get(url + "/health", timeout=1, trust_env=False)
                data = r.json() if r.status_code == 200 else {"tools": []}
            except (httpx.HTTPError, ValueError):
                data = {"tools": [], "message": "Контейнер сборщика не запущен или недоступен."}
            self.health[env] = (time.monotonic(), data)
            return data

    def status(self, tool):
        conf = self.store.public_config(tool.id)
        quota = self.store.quota(tool.id)
        state, reason = "ready", "Готов к запуску"
        if not conf["enabled"]:
            state, reason = "disabled", "Отключён в настройках"
        elif tool.key and not conf["has_key"]:
            state, reason = "requires_key", "Требуется API-ключ"
        elif tool.connection and not conf['connection_configured']:
            state, reason = 'requires_configuration', 'Укажите URL RPC или GraphSense API в настройках'
        elif tool.id == "geolite" and not any(Path(os.getenv("CHIMERA_GEOLITE", "geolite")).glob("GeoLite2-*.mmdb")):
            state, reason = "requires_database", "Требуется локальная база MMDB"
        elif tool.runner and tool.id not in self.runner_health(tool.runner).get("tools", []):
            state, reason = "requires_runner", self.runner_health(tool.runner).get("message", "Сборщик не установлен")
        elif quota.get("blocked_until", 0) > time.time():
            state, reason = "rate_limited", "Источник ограничил запросы"
        elif tool.daily and quota["used"] >= tool.daily:
            state, reason = "rate_limited", "Достигнута локальная суточная квота"
        return {**metadata(tool), **conf, "state": state, "reason": reason, "quota": quota, "verification": "Проверено подключение" if conf["checked_at"] else "Подключение не проверено"}

    def catalog(self):
        return [self.status(tool) for tool in TOOLS]

    def create(self, kind, value, selected, case_id=None, standalone=False, options=None):
        value = validate_target(kind, value)
        tools = list(dict.fromkeys(selected))
        if options is not None:
            from app.crypto import validate_options
            options = validate_options(tools, kind, options)
        if not tools or len(tools) > len(TOOLS) or any(id not in CATALOG or kind not in CATALOG[id].types for id in tools):
            raise ValueError("Выберите инструменты, поддерживающие тип запроса.")
        if sum(j["status"] in {"queued", "running"} for j in self.store.jobs()) >= 8:
            raise ValueError("Очередь заполнена: дождитесь завершения текущих исследований.")
        if case_id and not self.store.case(case_id):
            raise ValueError("Исследование не найдено.")
        runs = []
        for id in tools:
            status = self.status(CATALOG[id])
            runs.append({"tool": id, "name": CATALOG[id].name, "status": "queued" if status["state"] == "ready" else status["state"], "message": "В очереди" if status["state"] == "ready" else status["reason"]})
        job = {"id": uuid.uuid4().hex, "created": now(), "kind": kind, "value": value, "status": "queued", "runs": runs}
        if options is not None:
            job['options'] = options
        self.store.put_job(job)
        if not standalone:
            case_id = case_id or self.store.create_case(value[:120])["id"]
            self.store.attach_search(case_id, job["id"])
        self.pool.submit(self.execute, job)
        return {**job, "case_id": case_id}

    def execute(self, job):
        job["status"] = "running"
        self.store.put_job(job)
        for run in job["runs"]:
            if run["status"] != "queued":
                continue
            run.update(status="running", message="Запрос выполняется", started=now())
            self.store.put_job(job)
            id = run["tool"]
            try:
                # Recheck prerequisites after queueing; credential deletion/disable is immediate.
                status = self.status(CATALOG[id])
                if status["state"] != "ready":
                    raise ProviderError(status["state"], status["reason"])
                revision = self.store.config(id)["revision"]
                cache_id = hashlib.sha256(json.dumps([id, job["kind"], job["value"], revision]).encode()).hexdigest()
                if job.get('options') is not None:
                    cache_id += ':' + hashlib.sha256(json.dumps(job['options'], sort_keys=True).encode()).hexdigest()
                if id == "phoneinfoga":
                    cache_id += ":normalizer-1.1"
                with self.cache_locks[id]:
                    result = self.store.get_cache(cache_id)
                    cached = result is not None
                    if not cached:
                        tool = CATALOG[id]
                        args = (id, job['kind'], job['value']) + ((job['options'],) if job.get('options') is not None else ())
                        if tool.runner:
                            with self.runner_locks[tool.runner]:
                                result = self.store.redact(self.providers.run(*args))
                        else:
                            result = self.store.redact(self.providers.run(*args))
                        result["fetched_at"] = now()
                        if not result.get("partial"):
                            self.store.set_cache(cache_id, result)
                run.update(status="partial" if result.get("partial") else "completed", message="Частичные результаты" if result.get("partial") else "Получен ответ источника", result=result, cached=cached, adapter_version=result.get("normalizer_version", "1.0"))
            except ProviderError as e:
                run.update(status=e.status, message=e.message)
                if e.data is not None:
                    run["result"] = {"raw": self.store.redact(e.data), "summary": {}, "entities": [], "notes": [], "fetched_at": now()}
            except Exception:
                # Never serialize exception text: upstream clients can include authenticated URLs.
                run.update(status="error", message="Ошибка обработки ответа. Проверьте доступность и совместимость источника.")
            run["finished"] = now()
            self.store.put_job(job)
        complete = sum(r["status"] == "completed" for r in job["runs"])
        any_data = any(r["status"] in {"completed", "partial"} for r in job["runs"])
        job["status"] = "completed" if complete == len(job["runs"]) else "partial" if any_data else "failed"
        job["finished"] = now()
        self.store.put_job(job)

    def graph(self, job):
        nodes = {"target": {"id": "target", "type": job["kind"], "value": job["value"], "label": job["value"], "sources": []}}
        edges = {}
        for run in job["runs"]:
            if run["status"] in {"completed", "partial"}:
                nodes["target"]["sources"].append({"tool": run["tool"], "name": run["name"], "fetched_at": run["result"].get("fetched_at"), "relation": "исследован источником", "source_url": CATALOG[run["tool"]].source, "attributes": run["result"].get("summary", {})})
            for item in run.get("result", {}).get("entities", []):
                # Candidate IDs are provider-scoped; a matching name alone never merges people.
                namespace = run["tool"] if item["type"] == "candidate" else item.get("attributes", {}).get("network", "")
                ident = hashlib.sha256(json.dumps([item["type"], item["value"], namespace], ensure_ascii=False).encode()).hexdigest()[:16]
                if item["type"] == job["kind"] and item["value"] == job["value"]:
                    continue
                node = nodes.setdefault(ident, {"id": ident, "type": item["type"], "value": item["value"], "label": item.get("attributes", {}).get("label") or item["value"], "sources": []})
                evidence = {"tool": run["tool"], "name": run["name"], "fetched_at": run["result"].get("fetched_at"), **item}
                if evidence not in node["sources"]:
                    node["sources"].append(evidence)
                edge = edges.setdefault((ident, item["relation"]), {"source": "target", "target": ident, "relation": item["relation"], "sources": []})
                if run["tool"] not in edge["sources"]:
                    edge["sources"].append(run["tool"])
        return {"nodes": list(nodes.values()), "edges": list(edges.values())}

    def close(self):
        self.pool.shutdown(wait=True)

    def case_view(self, id):
        record = self.store.case(id)
        if not record:
            raise ValueError("Исследование не найдено.")
        searches = [{**j, "graph": self.graph(j)} for j in self.store.case_searches(id)]
        runs = [{**r, "run_id": j["id"] + ":" + r["tool"], "job_id": j["id"], "query": {"kind": j["kind"], "value": j["value"]}} for j in searches for r in j["runs"]]
        states = [j["status"] for j in searches]
        status = "draft" if not states else "running" if any(s in {"queued", "running"} for s in states) else "completed" if all(s == "completed" for s in states) else "partial" if any(s in {"completed", "partial"} for s in states) else "failed"
        return {**record, "kind": "case", "value": record["title"], "status": status, "searches": searches, "runs": runs, "graph": self.case_graph(record, searches)}

    def case_graph(self, record, searches):
        nodes = {"target": {"id": "target", "type": "case", "value": record["title"], "label": record["title"], "sources": [], "input_jobs": []}}
        edges = {}
        def ident(node):
            sources = node.get("sources", [])
            namespace = sources[0]["tool"] if node["type"] == "candidate" and sources else {"evm": "ethereum", "btc": "btc", "tron": "tron"}.get(node["type"], "")
            return hashlib.sha256(json.dumps([node["type"], node["value"], namespace], ensure_ascii=False).encode()).hexdigest()[:16]
        def edge(source, target, relation, evidence):
            key = (source, target, relation)
            item = edges.setdefault(key, {"source": source, "target": target, "relation": relation, "sources": [], "evidence": []})
            if evidence not in item["evidence"]:
                item["evidence"].append(evidence)
            for provider in evidence.get("sources", []):
                if provider not in item["sources"]:
                    item["sources"].append(provider)
        for search in searches:
            graph = search["graph"]
            ids = {}
            for original in graph["nodes"]:
                id = ident(original)
                ids[original["id"]] = id
                node = nodes.setdefault(id, {"id": id, "type": original["type"], "value": original["value"], "label": original["label"], "sources": [], "input_jobs": []})
                for evidence in original.get("sources", []):
                    enriched = {**evidence, "job_id": search["id"], "query": {"kind": search["kind"], "value": search["value"]}}
                    if enriched not in node["sources"]:
                        node["sources"].append(enriched)
                if original["id"] == "target":
                    node["input_jobs"].append({"job_id": search["id"], "association": search["association"], "note": search["association_note"]})
            input_id = ids["target"]
            # Case membership is an analyst assertion, never a provider-confirmed identity.
            edge("target", input_id, "данные исследования", {"job_id": search["id"], "association": search["association"], "note": search["association_note"], "asserted_by": "user", "sources": []})
            for original in graph["edges"]:
                source, target = ids[original["source"]], ids[original["target"]]
                if source != target:
                    edge(source, target, original["relation"], {"job_id": search["id"], "sources": original["sources"]})
        return {"nodes": list(nodes.values()), "edges": list(edges.values())}
