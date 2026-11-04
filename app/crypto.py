"""Bounded, read-only ledger exploration. No signing or transaction broadcast."""
import ipaddress
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Literal
from urllib.parse import quote, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.providers import ProviderError, output

TOOLS = {'esplora', 'trongrid', 'blockscout', 'graphsense', 'ethereumetl'}
CHAINS = {'1': ('Ethereum', 'ETH', 'https://etherscan.io'), '8453': ('Base', 'ETH', 'https://basescan.org'), '10': ('Optimism', 'ETH', 'https://optimistic.etherscan.io'), '534352': ('Scroll', 'ETH', 'https://scrollscan.com')}


class Options(BaseModel):
    model_config = ConfigDict(extra='forbid')
    chain: Literal['1', '8453', '10', '534352'] = '1'
    event: Literal['native', 'token', 'internal'] = 'native'
    pages: int = Field(default=1, ge=1, le=3)
    cursor: str = Field(default='', max_length=1024)
    direction: Literal['all', 'in', 'out'] = 'all'
    asset_filter: str = Field(default='', max_length=128)
    minimum: str = Field(default='', max_length=120)
    maximum: str = Field(default='', max_length=120)
    since: str = Field(default='', max_length=40)
    until: str = Field(default='', max_length=40)
    spend_checks: int = Field(default=2, ge=0, le=5)
    focus_txid: str = Field(default='', pattern=r'^(?:[0-9a-fA-F]{64})?$')
    start_block: int = Field(default=0, ge=0, le=10**10)
    end_block: int = Field(default=0, ge=0, le=10**10)

    @model_validator(mode='after')
    def bounds(self):
        for value in (self.minimum, self.maximum):
            if value and not re.fullmatch(r'\d{1,80}(?:\.\d{1,36})?', value):
                raise ValueError('Сумма должна быть неотрицательным десятичным числом.')
        if self.minimum and self.maximum and Decimal(self.minimum) > Decimal(self.maximum):
            raise ValueError('Минимальная сумма больше максимальной.')
        dates = [parse_time(v) for v in (self.since, self.until)]
        if all(x is not None for x in dates) and dates[0] > dates[1]:
            raise ValueError('Начальная дата позже конечной.')
        return self


def parse_time(value):
    if not value:
        return None
    d = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return d.replace(tzinfo=d.tzinfo or timezone.utc).timestamp()


def validate_options(tools, kind, options):
    if len(tools) != 1 or tools[0] not in TOOLS:
        raise ValueError('Параметры переводов доступны только для одной криптоутилиты.')
    if tools[0] == 'trongrid' and 'event' not in options:
        options = {**options, 'event': 'token'}
    o = Options.model_validate(options)
    if tools[0] == 'ethereumetl' and not 0 <= o.end_block-o.start_block < 20:
        raise ValueError('Ethereum ETL: укажите диапазон от 1 до 20 блоков.')
    if o.focus_txid and tools[0] != 'esplora':
        raise ValueError('Переход по расходованию выхода доступен для Bitcoin.')
    if tools[0] == 'esplora' and o.cursor and not re.fullmatch(r'[a-fA-F0-9]{64}', o.cursor):
        raise ValueError('Некорректный курсор Bitcoin.')
    if tools[0] == 'blockscout' and o.cursor and (not o.cursor.isdecimal() or not 1 <= int(o.cursor) <= 100000):
        raise ValueError('Некорректная страница Blockscout.')
    if tools[0] == 'trongrid' and o.event == 'internal':
        raise ValueError('Для TRON выберите TRX или токены TRC-20.')
    if tools[0] == 'graphsense' and kind == 'evm' and o.chain != '1':
        raise ValueError('Для GraphSense EVM используется индекс Ethereum.')
    return o.model_dump()


def endpoint(value):
    p = urlsplit(value)
    if p.port is not None and not 1 <= p.port <= 65535:
        raise ValueError('Некорректный порт подключения.')
    if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password or p.fragment or len(value) > 2048:
        raise ValueError('Укажите HTTP(S) URL без логина, пароля и фрагмента.')
    return value.rstrip('/')


def scaled(value, decimals):
    s = str(value)
    if not re.fullmatch(r'-?\d{1,120}', s) or not 0 <= int(decimals) <= 36:
        return None
    sign = '-' if s.startswith('-') else ''
    s = s.lstrip('-').lstrip('0') or '0'
    d = int(decimals)
    if not d:
        return sign+s
    s = s.zfill(d+1)
    return sign+(s[:-d]+'.'+s[-d:]).rstrip('0').rstrip('.')


def direction(address, senders, receivers):
    eq = lambda a: a.lower() == address.lower() if address.startswith('0x') else a == address
    incoming, outgoing = any(eq(a) for a in receivers), any(eq(a) for a in senders)
    return 'self' if incoming and outgoing else 'out' if outgoing else 'in' if incoming else 'related'


def row(txid, senders, receivers, amount, asset, stamp, network, address, **extra):
    stamp = int(stamp) if stamp not in (None, '') else None
    return {'txid': txid, 'from': senders, 'to': receivers, 'amount': amount, 'asset': asset, 'timestamp': stamp, 'network': network, 'direction': direction(address, senders, receivers), **extra}


def btc_rows(tx, address, spends=None):
    senders = list(dict.fromkeys((v.get('prevout') or {}).get('scriptpubkey_address') for v in tx.get('vin', []) if (v.get('prevout') or {}).get('scriptpubkey_address')))
    outgoing = address in senders
    result = []
    for n, vout in enumerate(tx.get('vout', [])):
        receiver = vout.get('scriptpubkey_address')
        if not outgoing and receiver != address:
            continue
        spend = spends[n] if isinstance(spends, list) and n < len(spends) else {}
        result.append(row(tx['txid'], senders, [receiver] if receiver else [], scaled(vout['value'], 8), 'BTC', tx.get('status', {}).get('block_time'), 'Bitcoin', address, index=n, atomic=str(vout['value']), confirmed=tx.get('status', {}).get('confirmed'), spent=spend.get('spent'), spending_txid=spend.get('txid'), tx_url='https://blockstream.info/tx/'+tx['txid']))
    return result


def tron_address(value):
    if not isinstance(value, str) or not re.fullmatch(r'41[0-9a-fA-F]{40}', value):
        return value
    raw = bytes.fromhex(value)
    data = raw+hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    number, result = int.from_bytes(data, 'big'), ''
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while number:
        number, n = divmod(number, 58); result = alphabet[n]+result
    return result


def tron_native(items):
    rows = []
    for tx in items:
        for contract in tx.get('raw_data', {}).get('contract', []):
            if contract.get('type') != 'TransferContract':
                continue
            data = contract.get('parameter', {}).get('value', {})
            rows.append({'transaction_id': tx.get('txID'), 'from': tron_address(data.get('owner_address')), 'to': tron_address(data.get('to_address')), 'value': data.get('amount', 0), 'block_timestamp': tx.get('block_timestamp'), 'isError': '0' if (tx.get('ret') or [{}])[0].get('contractRet') == 'SUCCESS' else '1'})
    return rows


def account_rows(items, address, network, native, explorer, event='native', tron=False, etl=False):
    rows = []
    for n, tx in enumerate(items):
        token = tx.get('token_info', {}) if tron else tx
        is_token = event == 'token'
        decimals = token.get('decimals', 0) if tron and is_token else tx.get('tokenDecimal') if is_token else 6 if tron else 18
        amount = scaled(tx.get('value', 0), int(decimals)) if decimals is not None and str(decimals).isdigit() else None
        txid = tx.get('transaction_id') or tx.get('hash') or tx.get('transaction_hash')
        stamp = tx.get('block_timestamp') if tron else tx.get('timeStamp', tx.get('block_timestamp'))
        if tron and stamp:
            stamp = int(stamp)//1000
        sender, receiver = tx.get('from', tx.get('from_address')), tx.get('to', tx.get('to_address'))
        if not txid:
            continue
        rows.append(row(txid, [sender] if sender else [], [receiver] if receiver else [], amount, token.get('symbol', 'TRC-20') if tron and is_token else tx.get('tokenSymbol', tx.get('token_address', 'Token')) if is_token else native, stamp, network, address, index=tx.get('logIndex', tx.get('log_index', tx.get('traceId', tx.get('trace_address', n)))), operation=event, contract=token.get('address') if tron and is_token else tx.get('contractAddress', tx.get('token_address')), atomic=str(tx.get('value', 0)), failed=tx.get('isError') == '1' or tx.get('status') == '0', tx_url=explorer+'/tx/'+txid if explorer else ''))
    return rows


def filtered(rows, o):
    result = []
    since, until = parse_time(o.since), parse_time(o.until)
    for r in rows:
        if o.direction != 'all' and r['direction'] != o.direction:
            continue
        if o.asset_filter and o.asset_filter.lower() not in {str(r.get('asset', '')).lower(), str(r.get('contract', '')).lower()}:
            continue
        if since is not None and (r.get('timestamp') is None or r['timestamp'] < since) or until is not None and (r.get('timestamp') is None or r['timestamp'] > until):
            continue
        if o.minimum or o.maximum:
            if r.get('amount') is None:
                continue
            value = Decimal(r['amount']).copy_abs()
            if o.minimum and value < Decimal(o.minimum) or o.maximum and value > Decimal(o.maximum):
                continue
        result.append(r)
    return result


def investigate(p, tool, kind, address, options):
    o = Options.model_validate(validate_options([tool], kind, options))
    raw, rows, notes, cursor, incomplete = {'pages': []}, [], [], o.cursor, False
    fetch = lambda url, params=None, headers=None: p.fetch(tool, url, params, headers)
    try:
        if tool == 'esplora':
            base = os.getenv('ESPLORA_URL', 'https://blockstream.info/api').rstrip('/')
            if cursor and not re.fullmatch(r'[a-fA-F0-9]{64}', cursor):
                raise ValueError('Некорректный курсор Bitcoin.')
            checks = o.spend_checks
            for _ in range(1 if o.focus_txid else o.pages):
                page = fetch(base+'/tx/'+o.focus_txid) if o.focus_txid else fetch(base+'/address/'+address+'/txs/chain'+('/'+cursor if cursor else ''))
                txs = [page] if o.focus_txid else page
                if not isinstance(txs, list) or any(not isinstance(tx, dict) or not tx.get('txid') or not isinstance(tx.get('vin'), list) or not isinstance(tx.get('vout'), list) for tx in txs):
                    raise ProviderError('source_error', 'Esplora вернул неподдерживаемую историю.')
                raw['pages'].append(page)
                for tx in txs:
                    spends = None
                    if checks:
                        try:
                            spends = fetch(base+'/tx/'+tx['txid']+'/outspends')
                            if not isinstance(spends, list) or len(spends) != len(tx['vout']) or any(not isinstance(s, dict) or not isinstance(s.get('spent'), bool) for s in spends):
                                raise ProviderError('source_error', 'Esplora не вернул список расходований.')
                            raw.setdefault('outspends', {})[tx['txid']] = spends
                        except ProviderError as e:
                            incomplete = True; notes.append(e.message)
                        checks -= 1
                    rows += btc_rows(tx, address, spends)
                cursor = txs[-1]['txid'] if not o.focus_txid and len(txs) == 25 else ''
                if not cursor:
                    break
            notes.append('Подтверждённая история BTC. Выходы общей транзакции не приписываются целиком одному входу; принадлежность сдачи не определяется. Расходования проверяются только в заданном бюджете.')
        elif tool == 'blockscout':
            page = int(cursor or '1')
            if not 1 <= page <= 100000:
                raise ValueError('Некорректная страница Blockscout.')
            for _ in range(o.pages):
                action = {'native': 'txlist', 'token': 'tokentx', 'internal': 'txlistinternal'}[o.event]
                data = fetch('https://api.blockscout.com/v2/api', {'chain_id': o.chain, 'module': 'account', 'action': action, 'address': address, 'page': page, 'offset': 50, 'sort': 'desc', 'apikey': p.store.key(tool)})
                if not isinstance(data, dict) or not isinstance(data.get('result'), list) or data.get('status') not in {'0', '1'}:
                    message = str(data.get('result', '')).lower() if isinstance(data, dict) else ''
                    raise ProviderError('rate_limited' if 'limit' in message else 'auth_error' if 'key' in message else 'source_error', 'Blockscout отклонил запрос; проверьте ключ, сеть и квоту.')
                if data['status'] == '0' and (data['result'] or 'no transactions' not in str(data.get('message', '')).lower() and 'no records' not in str(data.get('message', '')).lower()):
                    raise ProviderError('source_error', 'Blockscout не подтвердил успешное получение истории.')
                raw['pages'].append(data)
                rows += account_rows(data['result'], address, CHAINS[o.chain][0], CHAINS[o.chain][1], CHAINS[o.chain][2], o.event)
                page += 1
                cursor = str(page) if len(data['result']) == 50 else ''
                if not cursor:
                    break
        elif tool == 'trongrid':
            headers = {'TRON-PRO-API-KEY': p.store.key(tool)}
            if o.event == 'internal':
                raise ValueError('В этом адаптере TRON доступны обычные TRX и TRC-20.')
            for _ in range(o.pages):
                params = {'limit': 50, 'only_confirmed': 'true'}
                if cursor:
                    params['fingerprint'] = cursor
                data = fetch('https://api.trongrid.io/v1/accounts/'+address+'/transactions'+('/trc20' if o.event == 'token' else ''), params, headers)
                if not isinstance(data, dict) or data.get('success') is not True or not isinstance(data.get('data'), list):
                    raise ProviderError('source_error', 'TronGrid не подтвердил успешное получение истории.')
                raw['pages'].append(data)
                rows += account_rows(data['data'] if o.event == 'token' else tron_native(data['data']), address, 'TRON', 'TRX', '', o.event, tron=True)
                cursor = data.get('meta', {}).get('fingerprint', '') if data.get('meta', {}).get('links', {}).get('next') else ''
                if not cursor:
                    break
        elif tool == 'graphsense':
            base = p.store.endpoint(tool)
            if not base:
                raise ProviderError('requires_configuration', 'Укажите URL GraphSense API.')
            currency = {'btc': 'btc', 'evm': 'eth', 'tron': 'trx'}[kind]
            if kind == 'evm' and o.chain != '1':
                raise ValueError('Адаптер GraphSense для EVM использует индекс Ethereum (ETH).')
            headers = {'Authorization': p.store.key(tool)} if p.store.key(tool) else None
            for _ in range(o.pages):
                data = fetch(base+'/'+currency+'/addresses/'+quote(address, safe='')+'/txs', {'pagesize': 50, **({'page': cursor} if cursor else {})}, headers)
                if not isinstance(data, dict) or not isinstance(data.get('address_txs'), list):
                    raise ProviderError('source_error', 'GraphSense вернул несовместимую историю адреса.')
                raw['pages'].append(data)
                for n, tx in enumerate(data['address_txs']):
                    if not isinstance(tx, dict) or not tx.get('tx_hash') or not isinstance(tx.get('value'), dict) or not re.fullmatch(r'-?\d{1,120}', str(tx['value'].get('value', ''))):
                        incomplete = True
                        message = 'GraphSense: часть записей не содержит корректных TXID и атомарной суммы; они не считаются переводами.'
                        if message not in notes:
                            notes.append(message)
                        continue
                    val = tx.get('value', {}).get('value')
                    token = tx.get('currency', currency).upper()
                    r = row(tx.get('tx_hash', ''), [tx['from_address']] if tx.get('from_address') else [], [tx['to_address']] if tx.get('to_address') else [], scaled(val, 8 if kind == 'btc' else 6 if kind == 'tron' else 18), token, tx.get('timestamp'), currency, address, index=n, operation='net_change' if tx.get('tx_type') == 'utxo' else 'transfer', atomic=str(val))
                    if token != currency.upper():
                        r['amount'] = None  # Token decimals aren't inferred from its ticker.
                    if tx.get('tx_type') == 'utxo' and val is not None:
                        r['direction'] = 'out' if int(val) < 0 else 'in'
                    rows.append(r)
                cursor = data.get('next_page') or ''
                if not cursor:
                    break
            notes.append('GraphSense BTC показывает изменение баланса адреса, а не однозначный маршрут конкретных монет. Поддерживаемые валюты и полнота истории зависят от вашего индекса.')
        elif tool == 'ethereumetl':
            base, rpc = os.getenv('ETHEREUM_ETL_URL', ''), p.store.endpoint(tool)
            if not base or not rpc:
                raise ProviderError('requires_configuration', 'Настройте RPC и запустите профиль Docker crypto.')
            p.store.reserve(__import__('app.catalog', fromlist=['CATALOG']).CATALOG[tool])
            try:
                with httpx.Client(timeout=150, trust_env=False) as client:
                    response = client.post(base+'/run', json={'rpc': rpc, 'chain': o.chain, 'event': o.event, 'start': o.start_block, 'end': o.end_block, 'address': address})
                    response.raise_for_status(); data = response.json()
            except (httpx.HTTPError, ValueError):
                raise ProviderError('runner_unavailable', 'Сборщик Ethereum ETL не ответил.')
            if data.get('error'):
                raise ProviderError(data['error'], data.get('message', 'Ethereum ETL не завершил экспорт.'))
            raw['pages'].append(data)
            rows = account_rows(data.get('rows', []), address, CHAINS[o.chain][0], 'ETH', '', o.event, etl=True)
            cursor = ''; incomplete = bool(data.get('partial'))
            notes.append('Ethereum ETL: только указанный диапазон блоков. Для токенов сумма остаётся в атомарных единицах, пока не получены decimals; traces требуют совместимого RPC.')
    except ProviderError as e:
        if not raw['pages']:
            raise
        incomplete = True; notes.append(e.message)
    # Page boundaries and multi-output BTC require a record identity beyond TXID.
    unique = {json.dumps([r['txid'], r.get('index'), r.get('operation'), r.get('contract')], sort_keys=True): r for r in rows}
    visible = filtered(list(unique.values()), o)
    notes += ['Фильтры применены только к загруженным страницам. Продолжение по адресу выполняется вручную; переводы не доказывают общего владельца адресов.']
    crypto = {'rows': visible, 'loaded': len(unique), 'next_cursor': cursor if not incomplete else '', 'options': o.model_dump(), 'address': address, 'kind': kind}
    return {**output(raw, {'Загружено записей': len(unique), 'После фильтров': len(visible)}, notes=notes, partial=incomplete), 'crypto': crypto}
