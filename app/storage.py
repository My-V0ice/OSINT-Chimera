import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import quote

from cryptography.fernet import Fernet


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, data=None, secrets=None):
        self.root = Path(data or os.getenv("CHIMERA_DATA", ".local/data"))
        self.secrets = Path(secrets or os.getenv("CHIMERA_SECRETS", ".local/secrets"))
        self.root.mkdir(parents=True, exist_ok=True)
        self.secrets.mkdir(parents=True, exist_ok=True)
        keyfile = self.secrets / "master.key"
        if not keyfile.exists():
            try:
                with keyfile.open("xb") as out:
                    out.write(Fernet.generate_key())
                keyfile.chmod(0o600)
            except FileExistsError:
                pass
        self.cipher = Fernet(keyfile.read_bytes())
        self.path = self.root / "chimera.sqlite3"
        self.lock = threading.RLock()
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS settings (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 1, secret BLOB, revision INTEGER NOT NULL DEFAULT 0, checked TEXT);
            CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, endpoint BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, created TEXT, kind TEXT, value TEXT, status TEXT, data TEXT);
            CREATE TABLE IF NOT EXISTS quota (id TEXT PRIMARY KEY, day TEXT, used INTEGER DEFAULT 0, next_at REAL DEFAULT 0, blocked_until REAL DEFAULT 0, remaining INTEGER, reset TEXT);
            CREATE TABLE IF NOT EXISTS cache (id TEXT PRIMARY KEY, expires REAL, data TEXT);
            CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY, title TEXT NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS case_jobs (case_id TEXT NOT NULL, job_id TEXT NOT NULL, association TEXT NOT NULL DEFAULT 'hypothesis', note TEXT NOT NULL DEFAULT '', PRIMARY KEY(case_id,job_id));
            CREATE INDEX IF NOT EXISTS case_jobs_job ON case_jobs(job_id);
            CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def config(self, id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM settings WHERE id=?", (id,)).fetchone()
        return dict(row) if row else {"id": id, "enabled": 1, "secret": None, "revision": 0, "checked": None}

    def key(self, id):
        value = self.config(id)["secret"]
        return self.cipher.decrypt(value).decode() if value else ""

    def save_key(self, id, key):
        with self.lock, self.connect() as db:
            db.execute("INSERT OR IGNORE INTO settings(id) VALUES(?)", (id,))
            db.execute("UPDATE settings SET secret=?, revision=revision+1, checked=NULL WHERE id=?", (self.cipher.encrypt(key.encode()) if key else None, id))
            # A replaced credential may have a different allowance; only its old block is cleared.
            db.execute("UPDATE quota SET blocked_until=0, remaining=NULL, reset=NULL WHERE id=?", (id,))

    def enable(self, id, enabled):
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO settings(id) VALUES(?)", (id,))
            db.execute("UPDATE settings SET enabled=? WHERE id=?", (int(enabled), id))

    def endpoint(self, id):
        with self.connect() as db:
            row = db.execute('SELECT endpoint FROM connections WHERE id=?', (id,)).fetchone()
        return self.cipher.decrypt(row[0]).decode() if row else ''

    def save_endpoint(self, id, endpoint):
        with self.lock, self.connect() as db:
            db.execute('INSERT OR IGNORE INTO settings(id) VALUES(?)', (id,))
            if endpoint:
                db.execute('INSERT OR REPLACE INTO connections VALUES(?,?)', (id, self.cipher.encrypt(endpoint.encode())))
            else:
                db.execute('DELETE FROM connections WHERE id=?', (id,))
            db.execute('UPDATE settings SET revision=revision+1, checked=NULL WHERE id=?', (id,))

    def checked(self, id):
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO settings(id) VALUES(?)", (id,))
            db.execute("UPDATE settings SET checked=? WHERE id=?", (now(), id))

    def redact(self, value):
        with self.connect() as db:
            secrets = [self.cipher.decrypt(r[0]).decode() for r in db.execute("SELECT secret FROM settings WHERE secret IS NOT NULL")]
            secrets += [self.cipher.decrypt(r[0]).decode() for r in db.execute('SELECT endpoint FROM connections')]
        def scrub(obj):
            if isinstance(obj, dict):
                return {str(k): ("[скрыто]" if str(k).lower() in {"apikey", "api_key", "token", "authorization", "key", "tron-pro-api-key"} else scrub(v)) for k, v in obj.items()}
            if isinstance(obj, list):
                return [scrub(x) for x in obj]
            if isinstance(obj, str):
                for secret in secrets:
                    obj = obj.replace(secret, "[скрыто]").replace(quote(secret, safe=""), "[скрыто]")
                return obj
            return obj
        return scrub(value)

    def public_config(self, id):
        c = self.config(id)
        return {"enabled": bool(c["enabled"]), "has_key": bool(c["secret"]), "key_mask": "••••••••" if c["secret"] else "", "checked_at": c["checked"], 'connection_configured': bool(self.endpoint(id))}

    def quota(self, id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM quota WHERE id=?", (id,)).fetchone()
        result = dict(row) if row else {"used": 0, "remaining": None, "reset": None, "blocked_until": 0}
        if result.get("day") != datetime.now(timezone.utc).strftime("%Y-%m-%d"):
            result["used"] = 0
        return result

    def reserve(self, tool):
        """One process, all job threads share the same provider budget, including each HTTP call."""
        from app.providers import ProviderError
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self.lock, self.connect() as db:
            db.execute("INSERT OR IGNORE INTO quota(id,day) VALUES(?,?)", (tool.id, day))
            row = dict(db.execute("SELECT * FROM quota WHERE id=?", (tool.id,)).fetchone())
            used = row["used"] if row["day"] == day else 0
            current = time.time()
            if row["blocked_until"] > current:
                raise ProviderError("rate_limited", "Источник приостановлен до сброса ограничения.")
            if tool.daily and used >= tool.daily:
                raise ProviderError("rate_limited", "Достигнута локальная суточная квота.")
            slot = max(current, row["next_at"])
            db.execute("UPDATE quota SET day=?, used=?, next_at=? WHERE id=?", (day, used + 1, slot + tool.interval, tool.id))
        if slot > current:
            time.sleep(slot - current)

    def feedback(self, id, headers, blocked=False):
        remaining = headers.get("x-ratelimit-remaining")
        reset = headers.get("x-ratelimit-reset")
        retry = headers.get("retry-after", "60")
        try:
            delay = max(1, min(float(retry), 86400))
        except (TypeError, ValueError):
            from email.utils import parsedate_to_datetime
            try:
                delay = max(1, min(parsedate_to_datetime(retry).timestamp() - time.time(), 86400))
            except (TypeError, ValueError):
                delay = 60
        if blocked and reset:
            try:
                delay = max(delay, min(86400, float(reset) - time.time()))
            except ValueError:
                pass
        with self.connect() as db:
            db.execute("UPDATE quota SET remaining=?, reset=?, blocked_until=? WHERE id=?", (int(remaining) if str(remaining).isdigit() else None, reset, time.time() + delay if blocked else 0, id))

    def get_cache(self, id):
        with self.connect() as db:
            row = db.execute("SELECT data FROM cache WHERE id=? AND expires>?", (id, time.time())).fetchone()
        return json.loads(row[0]) if row else None

    def set_cache(self, id, data, ttl=900):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO cache VALUES(?,?,?)", (id, time.time() + ttl, json.dumps(self.redact(data), ensure_ascii=False)))

    def put_job(self, job):
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO jobs VALUES(?,?,?,?,?,?)", (job["id"], job["created"], job["kind"], job["value"], job["status"], json.dumps(self.redact(job), ensure_ascii=False)))

    def job(self, id):
        with self.connect() as db:
            row = db.execute("SELECT data FROM jobs WHERE id=?", (id,)).fetchone()
        return json.loads(row[0]) if row else None

    def jobs(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT id,created,kind,value,status FROM jobs ORDER BY created DESC LIMIT 100")]

    def tool_runs(self, tool):
        with self.connect() as db:
            rows = db.execute("""SELECT j.id,j.created,j.kind,j.value,json_extract(r.value,'$.status') AS status
                FROM jobs j,json_each(j.data,'$.runs') r WHERE json_extract(r.value,'$.tool')=?
                ORDER BY j.created DESC,j.id DESC LIMIT 100""", (tool,)).fetchall()
        return [dict(row) for row in rows]

    def create_case(self, title):
        title = title.strip()
        if not title or len(title) > 120 or any(ord(c) < 32 for c in title):
            raise ValueError("Название исследования: от 1 до 120 символов без управляющих знаков.")
        record = {"id": uuid.uuid4().hex, "title": title, "created": now(), "updated": now()}
        with self.connect() as db:
            db.execute("INSERT INTO cases VALUES(:id,:title,:created,:updated)", record)
        return record

    def case(self, id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM cases WHERE id=?", (id,)).fetchone()
        return dict(row) if row else None

    def rename_case(self, id, title):
        title = title.strip()
        if not title or len(title) > 120 or any(ord(c) < 32 for c in title):
            raise ValueError("Название исследования: от 1 до 120 символов без управляющих знаков.")
        with self.connect() as db:
            cursor = db.execute("UPDATE cases SET title=?,updated=? WHERE id=?", (title, now(), id))
            if not cursor.rowcount:
                raise ValueError("Исследование не найдено.")

    def cases(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute("""SELECT c.*, COUNT(j.id) AS search_count,
                COALESCE(SUM(j.status IN ('queued','running')),0) AS active_count
                FROM cases c LEFT JOIN case_jobs cj ON cj.case_id=c.id LEFT JOIN jobs j ON j.id=cj.job_id
                GROUP BY c.id ORDER BY c.updated DESC,c.id DESC""")]

    def case_searches(self, id):
        with self.connect() as db:
            rows = db.execute("""SELECT j.data,cj.association,cj.note FROM case_jobs cj
                JOIN jobs j ON j.id=cj.job_id WHERE cj.case_id=? ORDER BY j.created,j.id""", (id,)).fetchall()
        return [{**json.loads(row["data"]), "association": row["association"], "association_note": row["note"]} for row in rows]

    def attach_search(self, case_id, job_id):
        with self.lock, self.connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise ValueError("Исследование не найдено.")
            if not db.execute("SELECT 1 FROM jobs WHERE id=?", (job_id,)).fetchone():
                raise ValueError("Поиск не найден.")
            db.execute("INSERT OR IGNORE INTO case_jobs(case_id,job_id) VALUES(?,?)", (case_id, job_id))
            db.execute("UPDATE cases SET updated=? WHERE id=?", (now(), case_id))

    def detach_search(self, case_id, job_id):
        with self.connect() as db:
            db.execute("DELETE FROM case_jobs WHERE case_id=? AND job_id=?", (case_id, job_id))
            db.execute("UPDATE cases SET updated=? WHERE id=?", (now(), case_id))

    def set_association(self, case_id, job_id, association, note=""):
        if association not in {"hypothesis", "confirmed"} or len(note) > 2000:
            raise ValueError("Некорректное подтверждение связи.")
        with self.connect() as db:
            cursor = db.execute("UPDATE case_jobs SET association=?,note=? WHERE case_id=? AND job_id=?", (association, note, case_id, job_id))
            if not cursor.rowcount:
                raise ValueError("Поиск не входит в это исследование.")
            db.execute("UPDATE cases SET updated=? WHERE id=?", (now(), case_id))

    def migrate_cases(self):
        """Each ungrouped legacy search remains its own case; no inferred identities."""
        with self.lock, self.connect() as db:
            if db.execute("SELECT 1 FROM migrations WHERE name='cases-v1'").fetchone():
                return
            rows = db.execute("SELECT j.id,j.value,j.created FROM jobs j LEFT JOIN case_jobs cj ON cj.job_id=j.id WHERE cj.job_id IS NULL").fetchall()
            for row in rows:
                id = uuid.uuid4().hex
                db.execute("INSERT INTO cases VALUES(?,?,?,?)", (id, row["value"][:120], row["created"], row["created"]))
                db.execute("INSERT INTO case_jobs(case_id,job_id) VALUES(?,?)", (id, row["id"]))
            db.execute("INSERT INTO migrations VALUES('cases-v1')")

    def recover(self):
        with self.connect() as db:
            rows = db.execute("SELECT data FROM jobs WHERE status IN ('queued','running')").fetchall()
        for row in rows:
            job = json.loads(row[0])
            job["status"] = "interrupted"
            for run in job["runs"]:
                if run["status"] in {"queued", "running"}:
                    run.update(status="interrupted", message="Выполнение прервано перезапуском приложения.")
            self.put_job(job)

    def migrate_phoneinfoga(self):
        from app.phoneinfoga import normalize, VERSION
        with self.connect() as db:
            rows = db.execute("SELECT data FROM jobs WHERE data LIKE '%phoneinfoga%'").fetchall()
        count = 0
        for row in rows:
            job = json.loads(row[0])
            changed = False
            for run in job["runs"]:
                result = run.get("result", {})
                if run["tool"] != "phoneinfoga" or run["status"] not in {"completed", "partial"} or result.get("normalizer_version") == VERSION:
                    continue
                updated = normalize(result)
                if updated.get("normalizer_version") != VERSION:
                    continue
                run.update(result=updated, adapter_version=VERSION, status="partial" if updated["partial"] else "completed")
                changed = True
                count += 1
            if changed:
                if job["status"] == "completed" and any(r["status"] == "partial" for r in job["runs"]):
                    job["status"] = "partial"
                self.put_job(job)
        return count
