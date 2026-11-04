"""Read-only, fixed Ethereum ETL commands. Never return RPC URLs or CLI logs."""
import csv
import importlib.metadata
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, model_validator
from typing import Literal

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
lock = threading.Lock()


class Task(BaseModel):
    rpc: str = Field(max_length=2048)
    chain: Literal['1', '8453', '10', '534352']
    event: Literal['native', 'token', 'internal']
    start: int = Field(ge=0, le=10**10)
    end: int = Field(ge=0, le=10**10)
    address: str = Field(pattern=r'^0x[a-fA-F0-9]{40}$')

    @model_validator(mode='after')
    def limits(self):
        p = urlsplit(self.rpc)
        if not 0 <= self.end-self.start < 20 or p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password or p.fragment:
            raise ValueError('Invalid RPC or block range')
        return self


def command(t, target):
    cmd = {'native': 'export_blocks_and_transactions', 'token': 'export_token_transfers', 'internal': 'export_traces'}[t.event]
    return ['ethereumetl', cmd, '--start-block', str(t.start), '--end-block', str(t.end), '--provider-uri', t.rpc, '--max-workers', '1', '--batch-size', '5', '--transactions-output' if t.event == 'native' else '--output', str(target)]


@app.get('/health')
def health():
    ok = bool(shutil.which('ethereumetl'))
    return {'tools': ['ethereumetl'] if ok else [], 'status': 'ok' if ok else 'error'}


@app.post('/run')
def run(t: Task):
    if not lock.acquire(blocking=False):
        return {'error': 'runner_busy', 'message': 'Ethereum ETL занят другим экспортом.'}
    try:
        try:
            with httpx.Client(timeout=10, trust_env=False) as c:
                r = c.post(t.rpc, json={'jsonrpc': '2.0', 'id': 1, 'method': 'eth_chainId', 'params': []})
                r.raise_for_status()
                if int(r.json().get('result', ''), 16) != int(t.chain):
                    return {'error': 'source_error', 'message': 'Сеть RPC не совпадает с выбранной сетью.'}
        except (httpx.HTTPError, ValueError):
            return {'error': 'source_error', 'message': 'Не удалось проверить сеть RPC.'}
        with tempfile.TemporaryDirectory(prefix='chimera-etl-') as tmp:
            target = Path(tmp)/'transfers.csv'
            try:
                result = subprocess.run(command(t, target), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, cwd=tmp)
            except subprocess.TimeoutExpired:
                return {'error': 'timeout', 'message': 'Ethereum ETL превысил 120 секунд. Уменьшите диапазон блоков.'}
            except OSError:
                return {'error': 'requires_runner', 'message': 'Команда ethereumetl не установлена.'}
            if result.returncode != 0 or not target.exists():
                return {'error': 'source_error', 'message': 'Экспорт Ethereum ETL не завершён. Проверьте доступность RPC и поддержку выбранной операции.'}
            if target.stat().st_size > 4_000_000:
                return {'error': 'source_error', 'message': 'Экспорт превысил 4 МБ; уменьшите диапазон.'}
            with target.open() as f:
                rows = [r for r in csv.DictReader(f) if t.address.lower() in {r.get('from_address', '').lower(), r.get('to_address', '').lower()}]
            return {'rows': rows, 'start_block': t.start, 'end_block': t.end, 'version': importlib.metadata.version('ethereum-etl')}
    finally:
        lock.release()
