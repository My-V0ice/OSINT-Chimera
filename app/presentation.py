"""Display data without empty values, keeping 0/False and the original response intact."""
EMPTY = object()
from app.result_rules import profile_records, profiles_to_entities, harvester_records, spiderfoot_records, report_problems, pywhat_records


def compact(value):
    if value is None or isinstance(value, str) and not value.strip():
        return EMPTY
    if isinstance(value, dict):
        cleaned = {key: result for key, item in value.items() if (result := compact(item)) is not EMPTY}
        return cleaned if cleaned else EMPTY
    if isinstance(value, list):
        cleaned = [result for item in value if (result := compact(item)) is not EMPTY]
        return cleaned if cleaned else EMPTY
    return value



def present(tool, run):
    state = run["status"]
    result = run.get("result") or {}
    raw = result.get("raw", {})
    base = {"notes": result.get("notes", []), "summary": {}, "data": {}, "items": [], "searches": result.get("searches", [])}
    if state in {"queued", "running"}:
        return {**base, "state": "running"}
    if state == "not_found":
        return {**base, "state": "empty"}
    if state not in {"completed", "partial"}:
        diagnostics = compact(raw)
        return {**base, "state": "error", "diagnostics": {} if diagnostics is EMPTY else diagnostics}
    if isinstance(result.get('crypto'), dict):
        crypto = result['crypto']
        empty = not crypto.get('rows')
        return {**base, 'state': 'partial' if state == 'partial' else 'empty' if empty else 'success', 'empty': empty and state != 'partial', 'crypto': crypto, 'summary': result.get('summary', {}), 'data': {}, 'items': []}
    if not isinstance(raw, dict):
        cleaned = compact(raw)
        return {**base, "state": "partial" if state == "partial" else "empty" if cleaned is EMPTY else "success", "empty": cleaned is EMPTY and state != "partial", "data": {} if cleaned is EMPTY else cleaned}
    data = raw
    items = result.get("entities", [])
    empty = False
    summary = result.get("summary", {})
    reports = raw.get('reports', {})
    if tool in {'maigret', 'sherlock', 'holehe', 'theharvester', 'spiderfoot'} and report_problems(reports):
        state = 'partial'
    if tool in {"socialscan", "ignorant", "whatsmyname"}:
        checks = raw.get('account_checks', raw.get('account_findings', []))
        data = [row for row in raw.get('account_findings', []) if isinstance(row, dict) and row.get('status') in {'found', 'taken'} and not row.get('error') and row.get('rateLimit') not in (True, 'True', 'true')]
        if report_problems(checks):
            state = 'partial'
        items = []
        empty = not data
        summary = {"Находок": len(data), "Выполнено проверок": len(raw.get("account_checks", []))}
    elif tool == "github":
        data = raw.get("items", []) if "items" in raw else raw
        empty = not data
    elif tool == "phoneinfoga":
        data = raw.get("parsed", {}).get("local", {})
        empty = not data
    elif tool == "holehe":
        rows = raw.get("reports", {}).get("holehe.json", [])
        data = [row for row in rows if isinstance(row, dict) and row.get("exists") is True and not row.get("rateLimit") and not row.get("error")]
        summary = {"Сервисов с признаком регистрации": len(data)}
        empty = not data
        items = [{'type': 'service', 'value': row.get('name', 'unknown'), 'relation': 'признак регистрации email', 'source_url': 'https://' + row['domain'] if row.get('domain') else '', 'attributes': row} for row in data]
    elif tool in {"maigret", "sherlock"}:
        data = profile_records(reports)
        items = profiles_to_entities(data)
        summary = {"Найдено профилей": len(items)}
        empty = not data and not items
    elif tool in {"theharvester", "spiderfoot"}:
        data = harvester_records(reports) if tool == 'theharvester' else spiderfoot_records(reports)
        # Old stored entities can contain the echoed input or wrapper metadata.
        items = []
        summary = {"Найдено записей": len(data)}
        empty = not data
    elif tool == 'keybase':
        data = [row for row in raw.get('them', []) if isinstance(row, dict)]
        empty = not data
    elif tool == 'proxycheck':
        data = result.get('processed_data', {})
    elif tool == 'pywhat':
        data = pywhat_records(raw.get('reports', {}).get('pywhat.json', {}).get('Regexes'))
        empty = compact(data) is EMPTY
        summary = {}
    elif tool == "wikidata":
        data = raw.get("search", [])
        empty = not data
    elif tool == "openalex":
        data = raw.get("results", [])
        empty = not data
    elif tool == "geolite":
        data = {k: v for k, v in raw.items() if isinstance(v, dict) and not v.get("not_found")}
        empty = not data
    elif tool == "dns":
        if raw.get("status") == "NXDOMAIN":
            data, empty = {}, True
        else:
            data = {key: value for key, value in raw.items() if isinstance(value, dict) and value.get("values")}
            empty = not data
    elif tool == "internetdb":
        empty = not any(raw.get(key) for key in ("ports", "hostnames", "cpes", "vulns", "tags"))
    cleaned_data, cleaned_summary = compact(data), compact(summary)
    if cleaned_data is EMPTY and not items and not base["searches"]:
        empty = True
    return {**base, "state": "partial" if state == "partial" else "empty" if empty else "success", "empty": empty and state != "partial", "summary": {} if empty or cleaned_summary is EMPTY else cleaned_summary, "data": {} if cleaned_data is EMPTY else cleaned_data, "items": [] if empty else items, "diagnostics": {key: raw[key] for key in ("stdout", "stderr", "exit_code", "timed_out", "tool_version") if key in raw}}
