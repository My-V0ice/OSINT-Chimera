"""Source-specific evidence rules, shared by the API and isolated runners."""
import ipaddress
import re


def unique(rows):
    import json
    seen, result = set(), []
    for row in rows:
        key = json.dumps(row, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            result.append(row)
    return result


def profile_records(value):
    rows = []
    def visit(obj):
        if isinstance(obj, list):
            for item in obj:
                visit(item)
        elif isinstance(obj, dict):
            status = obj.get('status', obj.get('exists'))
            if isinstance(status, dict):
                status = status.get('status')
            if status is not None:
                if str(status).strip().lower() not in {'true', 'found', 'claimed', 'maigretcheckstatus.claimed'}:
                    return
                url = obj.get('url_user') or obj.get('profile_url') or obj.get('url')
                if isinstance(url, str) and url.startswith(('https://', 'http://')):
                    rows.append({k: v for k, v in obj.items() if k not in {'site', 'cookies'}})
                return  # Don't count the nested status a second time.
            for item in obj.values():
                visit(item)
    visit(value)
    return unique(rows)


def profiles_to_entities(rows):
    result, seen = [], set()
    for row in rows:
        url = row.get('url_user') or row.get('profile_url') or row.get('url')
        if url and url not in seen:
            seen.add(url)
            result.append({'type': 'profile', 'value': url, 'relation': 'возможный аккаунт', 'source_url': url, 'attributes': {'confirmed_owner': False}})
    return result


def harvester_records(value):
    """Ignore execution summaries, commands, target echoes and counters."""
    rows = []
    kinds = {'emails': 'email', 'email': 'email', 'email_addresses': 'email', 'hosts': 'host', 'hostnames': 'host', 'domains': 'domain', 'ips': 'ip', 'ip_addresses': 'ip'}
    def add(kind, item):
        if isinstance(item, dict):
            candidate = item.get('value') or item.get('data') or item.get('host') or item.get('email') or item.get('ip')
            if candidate:
                add(kind, candidate)
            return
        if not isinstance(item, str) or not item.strip():
            return
        item = item.strip()
        if kind == 'email' and re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', item):
            rows.append({'type': 'email', 'value': item})
        elif kind in {'ip', 'host'}:
            try:
                rows.append({'type': 'ip', 'value': str(ipaddress.ip_address(item))})
                return
            except ValueError:
                if kind == 'ip':
                    return
            # Older JSON combines hostname:IP in one host string.
            host, sep, address = item.partition(':')
            if re.fullmatch(r'[\w*-][\w.*-]*\.[A-Za-z]{2,}', host):
                rows.append({'type': 'domain', 'value': host.lstrip('*.')})
            if sep:
                add('ip', address)
        elif kind == 'domain' and re.fullmatch(r'[\w*-][\w.*-]*\.[A-Za-z]{2,}', item):
            rows.append({'type': 'domain', 'value': item.lstrip('*.')})
    def visit(obj):
        if isinstance(obj, list):
            for item in obj:
                visit(item)
        elif isinstance(obj, dict):
            artifact_type = str(obj.get('type', '')).lower()
            if artifact_type in {'email', 'email_address', 'ip', 'ip_address', 'domain', 'hostname', 'host'}:
                add({'email_address': 'email', 'ip_address': 'ip', 'hostname': 'host'}.get(artifact_type, artifact_type), obj)
            for key, item in obj.items():
                if key.lower() in kinds:
                    for entry in item if isinstance(item, list) else [item]:
                        add(kinds[key.lower()], entry)
                elif key in {'artifacts', 'results', 'data'} or isinstance(item, (dict, list)) and key.endswith(('.json', '.jsonl')):
                    visit(item)
    visit(value)
    return unique(rows)


def spiderfoot_records(value):
    events = value.get('events', []) if isinstance(value, dict) else value
    if not isinstance(events, list):
        return []
    return unique([row for row in events if isinstance(row, dict) and row.get('data') not in (None, '', [], {}) and str(row.get('module', '')).startswith('sfp_') and str(row.get('type', '')).upper() not in {'ROOT', 'ERROR', 'DEBUG', 'INFO'}])


def report_problems(value):
    if isinstance(value, list):
        return any(report_problems(item) for item in value)
    if not isinstance(value, dict):
        return False
    status = value.get('status', '')
    if isinstance(status, dict):
        status = status.get('status', '')
    if value.get('parse_error') or value.get('error') or value.get('rateLimit') in (True, 'True', 'true') or str(status).lower() in {'unknown', 'error', 'failed', 'blocked', 'timeout'}:
        return True
    if value.get('evidence_status') in {'partial', 'failed', 'error', 'incomplete'}:
        return True
    return any(report_problems(item) for key, item in value.items() if key not in {'site', 'cookies', 'headers'} and isinstance(item, (dict, list)))


def pywhat_records(value):
    rows = []
    for matches in (value or {}).values():
        for match in matches if isinstance(matches, list) else []:
            if not isinstance(match, dict) or not match.get('Matched'):
                continue
            pattern = match.get('Regex Pattern', match.get('Regex', {}))
            if isinstance(pattern, dict) and pattern.get('Name'):
                rows.append({'matched': match['Matched'], 'possible_type': pattern['Name'], 'description': pattern.get('Description'), 'rarity': pattern.get('Rarity'), 'tags': pattern.get('Tags'), 'url': pattern.get('URL')})
    return unique(rows)
