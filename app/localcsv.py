"""Local, streaming CSV ingestion and indexed searches. No external services."""
import codecs
import csv
import hashlib
import json
import re
import sqlite3
import threading
import time
import unicodedata
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from app.storage import now


class CSVSearch(BaseModel):
    query: str = Field(min_length=2, max_length=254)
    field: str = Field(default='', max_length=256)
    sources: list[str] = Field(default_factory=list, max_length=1000)
    mode: Literal['contains', 'exact'] = 'contains'
    cursor: int = Field(default=0, ge=0)
    limit: int = Field(default=30, ge=1, le=50)


def normalize(value):
    value = ' '.join(unicodedata.normalize('NFKC', str(value)).casefold().replace('ё', 'е').split())
    if re.fullmatch(r'[+\d\s().-]+', value) and len(re.sub(r'\D', '', value)) >= 7:
        return re.sub(r'\D', '', value)
    return value


def detect(path, encoding='auto', delimiter='auto'):
    if encoding not in {'auto', 'utf-8-sig', 'cp1251', 'utf-16'}:
        raise ValueError('Неизвестная кодировка CSV.')
    if delimiter not in {'auto', ',', ';', '\t', '|'}:
        raise ValueError('Неизвестный разделитель CSV.')
    with path.open('rb') as stream:
        sample = stream.read(131072)
    if not sample:
        raise ValueError('Файл пуст.')
    if encoding == 'auto':
        if sample.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
            encoding = 'utf-16'
        else:
            try:
                codecs.getincrementaldecoder('utf-8-sig')().decode(sample, final=False)
                encoding = 'utf-8-sig'
            except UnicodeDecodeError:
                encoding = 'cp1251'
    text = codecs.getincrementaldecoder(encoding)().decode(sample, final=False)
    if '\0' in text:
        raise ValueError('Файл содержит нулевые байты. Проверьте формат и кодировку.')
    if delimiter == 'auto':
        # Header delimiters remain useful even when sample records have unequal lengths.
        try:
            delimiter = csv.Sniffer().sniff(text, delimiters=',;\t|').delimiter
        except csv.Error:
            header = text.splitlines()[0]
            delimiter = max(',;\t|', key=header.count)
            if header.count(delimiter) == 0:
                delimiter = ','
    return encoding, delimiter


class LocalCSV:
    def __init__(self, root):
        self.root = Path(root) / 'csv'
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / 'index.sqlite3'
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='csv-import')
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        with self.connect() as db:
            db.executescript('''
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS sources (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, digest TEXT UNIQUE NOT NULL,
                    size INTEGER NOT NULL, status TEXT NOT NULL, rows INTEGER NOT NULL DEFAULT 0,
                    headers TEXT NOT NULL DEFAULT '[]', encoding TEXT, delimiter TEXT,
                    created TEXT NOT NULL, message TEXT NOT NULL DEFAULT '', archived INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL, line INTEGER NOT NULL,
                    data TEXT NOT NULL, norm TEXT NOT NULL, search_text TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS records_source ON records(source_id);
                CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(
                    search_text, content='records', content_rowid='id', tokenize='trigram'
                );
                CREATE TRIGGER IF NOT EXISTS records_insert AFTER INSERT ON records BEGIN
                    INSERT INTO search_index(rowid, search_text) VALUES(new.id, new.search_text);
                END;
                CREATE TRIGGER IF NOT EXISTS records_delete AFTER DELETE ON records BEGIN
                    INSERT INTO search_index(search_index,rowid,search_text) VALUES('delete',old.id,old.search_text);
                END;
            ''')
            interrupted = [r[0] for r in db.execute("SELECT id FROM sources WHERE status='importing'")]
            for id in interrupted:
                db.execute('DELETE FROM records WHERE source_id=?', (id,))
            db.execute("UPDATE sources SET status='failed', rows=0, message='Импорт прерван перезапуском. Загрузите файл повторно.' WHERE status='importing'")
        for file in self.root.glob('*.upload'):
            file.unlink(missing_ok=True)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def close(self):
        self.stopping.set()
        self.pool.shutdown(wait=True)

    def sources(self):
        with self.connect() as db:
            rows = db.execute('SELECT * FROM sources ORDER BY created DESC, id').fetchall()
        return [self.public(row) for row in rows]

    @staticmethod
    def public(row):
        d = dict(row)
        d.pop('digest', None)
        d['headers'] = json.loads(d['headers'])
        d['archived'] = bool(d['archived'])
        return d

    def enqueue(self, path, name, size, digest, encoding='auto', delimiter='auto'):
        try:
            encoding, delimiter = detect(path, encoding, delimiter)
            signature = hashlib.sha256((digest + encoding + delimiter).encode()).hexdigest()
            with self.lock, self.connect() as db:
                existing = db.execute('SELECT * FROM sources WHERE digest=?', (signature,)).fetchone()
                if existing and existing['status'] != 'failed':
                    path.unlink(missing_ok=True)
                    return {**self.public(existing), 'duplicate': True}
                if existing:
                    db.execute('DELETE FROM sources WHERE id=?', (existing['id'],))
                if db.execute("SELECT count(*) FROM sources WHERE status='importing'").fetchone()[0] >= 12:
                    raise ValueError('Очередь импорта заполнена. Дождитесь завершения файлов.')
                id = uuid.uuid4().hex
                db.execute('INSERT INTO sources(id,name,digest,size,status,encoding,delimiter,created) VALUES(?,?,?,?,?,?,?,?)',
                           (id, name, signature, size, 'importing', encoding, delimiter, now()))
            self.pool.submit(self.ingest, id, path, encoding, delimiter)
            return next(s for s in self.sources() if s['id'] == id)
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def ingest(self, id, path, encoding, delimiter):
        count = 0
        warning = False
        try:
            csv.field_size_limit(1024 * 1024)
            with path.open('r', encoding=encoding, newline='') as stream:
                reader = csv.reader(stream, delimiter=delimiter, strict=True)
                header = next(reader)
                if not header or len(header) > 256:
                    raise ValueError('В CSV должно быть от 1 до 256 столбцов.')
                headers, used = [], set()
                for i, value in enumerate(header):
                    key = value.strip() or f'column_{i + 1}'
                    if len(key) > 240:
                        raise ValueError('Название столбца слишком длинное (максимум 240 символов).')
                    base, n = key, 2
                    while key in used:
                        key = f'{base}_{n}'
                        n += 1
                    headers.append(key)
                    used.add(key)
                warning = any('\ufffd' in key for key in headers)
                with self.connect() as db:
                    db.execute('UPDATE sources SET headers=? WHERE id=?', (json.dumps(headers, ensure_ascii=False), id))
                batch = []
                while True:
                    if self.stopping.is_set():
                        raise ValueError('Импорт прерван остановкой приложения. Загрузите файл повторно.')
                    line = reader.line_num + 1
                    try:
                        values = next(reader)
                    except StopIteration:
                        break
                    if not values or not any(v.strip() for v in values):
                        continue
                    if len(values) > len(headers):
                        raise ValueError(f'Строка {line}: столбцов больше, чем в заголовке. Проверьте разделитель.')
                    if sum(map(len, values)) > 2 * 1024 * 1024:
                        raise ValueError(f'Строка {line} превышает 2 МиБ.')
                    values += [''] * (len(headers) - len(values))
                    warning |= any('\ufffd' in value for value in values)
                    record = dict(zip(headers, values))
                    norm = {k: normalize(v) for k, v in record.items()}
                    batch.append((id, line, json.dumps(record, ensure_ascii=False), json.dumps(norm, ensure_ascii=False), ' '.join(norm.values())))
                    count += 1
                    if len(batch) >= 1000:
                        self.insert_batch(id, batch, count)
                        batch = []
                if batch:
                    self.insert_batch(id, batch, count)
            message = 'В исходном файле есть символы замены �. Уже повреждённый текст восстановить автоматически нельзя.' if warning else ''
            with self.connect() as db:
                db.execute("UPDATE sources SET status='ready', rows=?, message=? WHERE id=?", (count, message, id))
        except (ValueError, UnicodeError, csv.Error, StopIteration) as error:
            # Parsing errors never include record contents or sample personal data.
            message = str(error) if isinstance(error, ValueError) and not isinstance(error, UnicodeError) else 'CSV не прочитан. Проверьте кодировку, разделитель и кавычки.'
            self.fail(id, message)
        except Exception:
            self.fail(id, 'Не удалось создать локальный индекс. Проверьте свободное место и загрузите файл повторно.')
        finally:
            path.unlink(missing_ok=True)

    def insert_batch(self, id, batch, count):
        with self.connect() as db:
            db.executemany('INSERT INTO records(source_id,line,data,norm,search_text) VALUES(?,?,?,?,?)', batch)
            db.execute('UPDATE sources SET rows=? WHERE id=?', (count, id))

    def fail(self, id, message):
        with self.connect() as db:
            db.execute('DELETE FROM records WHERE source_id=?', (id,))
            db.execute("UPDATE sources SET status='failed', rows=0, message=? WHERE id=?", (message, id))

    def archive(self, id, archived):
        with self.connect() as db:
            if not db.execute('UPDATE sources SET archived=? WHERE id=?', (int(archived), id)).rowcount:
                raise ValueError('Файл не найден.')

    def search(self, query):
        needle = normalize(query.query)
        if len(needle) < 2:
            raise ValueError('Введите минимум два символа для поиска.')
        where = ["s.status='ready'", 's.archived=0', 'r.id>?']
        args = [query.cursor]
        if query.sources:
            where.append('s.id IN (' + ','.join('?' for _ in query.sources) + ')')
            args.extend(query.sources)
        # Quotes turn the user text into an FTS literal, never an FTS expression.
        if len(needle) >= 3:
            where.append('r.id IN (SELECT rowid FROM search_index WHERE search_index MATCH ?)')
            args.append('"' + needle.replace('"', '""') + '"')
        if query.mode == 'contains' and not query.field:
            where.append('instr(r.search_text,?)>0')
            args.append(needle)
        else:
            clause = 'value=?' if query.mode == 'exact' else 'instr(value,?)>0'
            where.append('EXISTS(SELECT 1 FROM json_each(r.norm) WHERE ' + ('key=? AND ' if query.field else '') + clause + ')')
            if query.field:
                args.append(query.field)
            args.append(needle)
        start = time.monotonic()
        try:
            with self.connect() as db:
                db.set_progress_handler(lambda: int(time.monotonic() - start > 8), 10000)
                rows = db.execute('SELECT r.id,r.line,r.data,s.id AS source_id,s.name FROM records r JOIN sources s ON s.id=r.source_id WHERE '
                                  + ' AND '.join(where) + ' ORDER BY r.id LIMIT ?', (*args, query.limit + 1)).fetchall()
        except sqlite3.OperationalError as e:
            if 'interrupt' in str(e):
                raise ValueError('Поиск занял больше 8 секунд. Уточните запрос или выберите файлы.') from None
            raise
        more = len(rows) > query.limit
        rows = rows[:query.limit]
        return {'query': query.model_dump(), 'created': now(), 'matches': [
            {'id': r['id'], 'source_id': r['source_id'], 'source': r['name'], 'line': r['line'], 'data': json.loads(r['data'])} for r in rows
        ], 'next_cursor': rows[-1]['id'] if more else None, 'has_more': more,
                'returned': len(rows), 'scope': 'Только готовые файлы, не находящиеся в архиве.'}
