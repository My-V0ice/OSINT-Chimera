import os
import secrets
import hashlib
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.catalog import CATALOG, TYPES
from app.storage import Store
from app.service import Engine
from app.providers import ProviderError
from app.presentation import present
from app.localcsv import LocalCSV, CSVSearch


class Search(BaseModel):
    kind: str
    value: str = Field(min_length=1, max_length=254)
    tools: list[str] = Field(min_length=1, max_length=len(CATALOG))
    case_id: str | None = Field(default=None, max_length=64)


class ToolQuery(BaseModel):
    kind: str
    value: str = Field(min_length=1, max_length=254)
    options: dict | None = None


class Connection(BaseModel):
    endpoint: str = Field(default='', max_length=2048)


class CaseTitle(BaseModel):
    title: str = Field(min_length=1, max_length=120)


class SearchLink(BaseModel):
    job_id: str = Field(min_length=1, max_length=64)


class Association(BaseModel):
    association: str
    note: str = Field(default="", max_length=2000)


class KeyUpdate(BaseModel):
    key: str = Field(min_length=1, max_length=512)


class Toggle(BaseModel):
    enabled: bool


class CSVArchive(BaseModel):
    archived: bool


def create_app(store=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.store = store or Store()
        app.state.engine = Engine(app.state.store)
        app.state.csv = LocalCSV(app.state.store.root)
        app.state.csrf = secrets.token_urlsafe(32)
        yield
        app.state.csv.close()
        app.state.engine.close()

    app = FastAPI(title="OSINT-Химера", version="0.7.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"])

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail": "Недопустимый источник запроса."}, status_code=403)
            token = request.headers.get("x-chimera-csrf", "")
            cookie = request.cookies.get("chimera_session", "")
            if not secrets.compare_digest(token, getattr(app.state, "csrf", "")) or not cookie or not secrets.compare_digest(token, cookie):
                return JSONResponse({"detail": "Обновите страницу перед изменением данных."}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.7.0"}

    @app.get("/api/bootstrap")
    def bootstrap():
        response = JSONResponse({"csrf": app.state.csrf, "types": TYPES, "version": "0.7.0"})
        response.set_cookie("chimera_session", app.state.csrf, httponly=True, samesite="strict")
        return response

    @app.get("/api/tools")
    def tools():
        return app.state.engine.catalog()

    @app.get('/api/local-csv/sources')
    def csv_sources():
        return {'sources': app.state.csv.sources(), 'max_file_bytes': 512 * 1024 * 1024}

    @app.post('/api/local-csv/sources', status_code=202)
    async def csv_upload(request: Request, name: str, encoding: str = 'auto', delimiter: str = 'auto'):
        name = name.replace('\\', '/').split('/')[-1].strip()
        if not name.lower().endswith('.csv') or len(name) > 200 or any(ord(c) < 32 for c in name):
            raise HTTPException(400, 'Выберите CSV-файл с именем до 200 символов.')
        path = app.state.csv.root / (uuid.uuid4().hex + '.upload')
        size, digest, handed_off = 0, hashlib.sha256(), False
        try:
            with path.open('xb') as stream:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > 512 * 1024 * 1024:
                        raise HTTPException(413, 'Максимальный размер одного CSV — 512 МиБ.')
                    digest.update(chunk)
                    stream.write(chunk)
            result = app.state.csv.enqueue(path, name, size, digest.hexdigest(), encoding, delimiter)
            handed_off = True
            return result
        except ValueError as e:
            raise HTTPException(400, str(e))
        finally:
            # Successful enqueue owns the file until the importer finishes.
            # An HTTP disconnect or rejected upload must not leave a partial file.
            if not handed_off:
                path.unlink(missing_ok=True)

    @app.put('/api/local-csv/sources/{id}/archive')
    def csv_archive(id: str, update: CSVArchive):
        try:
            app.state.csv.archive(id, update.archived)
        except ValueError as e:
            raise HTTPException(404, str(e))
        return {'ok': True}

    @app.post('/api/local-csv/search')
    def csv_search(query: CSVSearch):
        try:
            return app.state.csv.search(query)
        except ValueError as e:
            raise HTTPException(400, str(e))

    def tool_id(id):
        if id not in CATALOG:
            raise HTTPException(404, "Инструмент не найден.")
        return CATALOG[id]

    @app.get("/api/tools/{id}/runs")
    def tool_runs(id: str):
        tool_id(id)
        return app.state.store.tool_runs(id)

    @app.post("/api/tools/{id}/runs", status_code=202)
    def run_tool(id: str, query: ToolQuery):
        tool_id(id)
        try:
            return app.state.engine.create(query.kind, query.value, [id], standalone=True, options=query.options)
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.get("/api/tools/{id}/runs/{job_id}")
    def tool_result(id: str, job_id: str):
        tool_id(id)
        job = app.state.store.job(job_id)
        run = next((r for r in job["runs"] if r["tool"] == id), None) if job else None
        if run is None:
            raise HTTPException(404, "Запуск этой утилиты не найден.")
        return {"id": job["id"], "created": job["created"], "kind": job["kind"], "value": job["value"], 'options': job.get('options'), "run": run, "presentation": present(id, run), "raw_json": run.get("result", {}).get("raw", {"status": run["status"], "message": run.get("message")})}

    @app.put('/api/tools/{id}/connection')
    def set_connection(id: str, config: Connection):
        if not tool_id(id).connection:
            raise HTTPException(400, 'Утилита не поддерживает настройку подключения.')
        try:
            from app.crypto import endpoint
            value = endpoint(config.endpoint.strip()) if config.endpoint.strip() else ''
        except ValueError as e:
            raise HTTPException(400, str(e))
        app.state.store.save_endpoint(id, value)
        return app.state.engine.status(CATALOG[id])

    @app.get("/api/tools/{id}/runs/{job_id}/export")
    def export_tool_result(id: str, job_id: str):
        return JSONResponse(tool_result(id, job_id), headers={"Content-Disposition": f'attachment; filename="chimera-{id}-{job_id[:32]}.json"'})

    @app.put("/api/tools/{id}/key")
    def key_update(id: str, update: KeyUpdate):
        tool = tool_id(id)
        key = update.key.strip()
        if not (tool.key or tool.optional_key) or not key or any(c.isspace() for c in key):
            raise HTTPException(400, "Некорректный ключ или инструмент не использует общий ключ.")
        app.state.store.save_key(id, key)
        return app.state.engine.status(tool)

    @app.delete("/api/tools/{id}/key")
    def key_delete(id: str):
        tool = tool_id(id)
        app.state.store.save_key(id, "")
        return app.state.engine.status(tool)

    @app.put("/api/tools/{id}/enabled")
    def enabled(id: str, toggle: Toggle):
        tool = tool_id(id)
        app.state.store.enable(id, toggle.enabled)
        return app.state.engine.status(tool)

    @app.post("/api/tools/{id}/check")
    def check(id: str):
        tool = tool_id(id)
        status = app.state.engine.status(tool)
        if status["state"] != "ready":
            return {"ok": False, "status": status["state"], "message": status["reason"]}
        # An explicit user action: small fixed lookup, not an automatic credential test on startup.
        targets = {"ipinfo": ("ip", "8.8.8.8"), "abuseipdb": ("ip", "8.8.8.8"), "etherscan": ("evm", "0x0000000000000000000000000000000000000000"), "trongrid": ("tron", "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7"), "openalex": ("person", "Ada Lovelace"), "github": ("username", "octocat"), "proxycheck": ("ip", "8.8.8.8"), "gravatar": ("email", "support@gravatar.com")}
        if id not in targets:
            return {"ok": True, "status": "available", "message": "Компонент доступен. Проверка источника выполнится при исследовании."}
        try:
            result = app.state.engine.providers.run(id, *targets[id])
            if result.get("partial"):
                return {"ok": False, "status": "partial", "message": "Доступны не все операции. Ключ не отмечен проверенным."}
            app.state.store.checked(id)
            return {"ok": True, "status": "verified", "message": "Источник принял запрос. Ключ сохранён и проверен."}
        except ProviderError as e:
            return {"ok": False, "status": e.status, "message": e.message}
        except Exception:
            return {"ok": False, "status": "error", "message": "Не удалось проверить подключение."}

    @app.get("/api/jobs")
    def jobs():
        return app.state.store.jobs()

    @app.post("/api/jobs", status_code=202)
    def create_job(search: Search):
        if search.kind not in TYPES:
            raise HTTPException(400, "Неизвестный тип запроса.")
        try:
            return app.state.engine.create(search.kind, search.value, search.tools, search.case_id)
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.get("/api/jobs/{id}")
    def get_job(id: str):
        job = app.state.store.job(id)
        if not job:
            raise HTTPException(404, "Исследование не найдено.")
        return {**job, "graph": app.state.engine.graph(job)}

    @app.get("/api/jobs/{id}/export")
    def export(id: str):
        data = get_job(id)
        return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="chimera-{data["id"]}.json"'})

    @app.get("/api/cases")
    def cases():
        return app.state.store.cases()

    @app.post("/api/cases", status_code=201)
    def create_case(record: CaseTitle):
        try:
            return app.state.store.create_case(record.title)
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.get("/api/cases/{id}")
    def get_case(id: str):
        try:
            return app.state.engine.case_view(id)
        except ValueError as e:
            raise HTTPException(404, str(e))

    @app.put("/api/cases/{id}")
    def rename_case(id: str, record: CaseTitle):
        get_case(id)
        try:
            app.state.store.rename_case(id, record.title)
            return get_case(id)
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.post("/api/cases/{id}/searches")
    def attach_search(id: str, link: SearchLink):
        get_case(id)
        try:
            app.state.store.attach_search(id, link.job_id)
            return get_case(id)
        except ValueError as e:
            raise HTTPException(404, str(e))

    @app.delete("/api/cases/{id}/searches/{job_id}")
    def detach_search(id: str, job_id: str):
        get_case(id)
        app.state.store.detach_search(id, job_id)
        return get_case(id)

    @app.put("/api/cases/{id}/searches/{job_id}")
    def association(id: str, job_id: str, update: Association):
        get_case(id)
        try:
            app.state.store.set_association(id, job_id, update.association, update.note)
            return get_case(id)
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.get("/api/cases/{id}/export")
    def export_case(id: str):
        data = get_case(id)
        return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="chimera-case-{data["id"]}.json"'})

    static = Path(__file__).parent / "static"
    @app.get("/")
    def index():
        return FileResponse(static / "index.html")

    app.mount("/static", StaticFiles(directory=static), name="static")
    return app


app = create_app()
