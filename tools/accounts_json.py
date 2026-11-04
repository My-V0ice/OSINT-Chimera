"""Bounded adapters; no passwords, recovery messages, proxy rotation or auto-update."""
import json
import sys
from pathlib import Path

WMN_REVISION = "35576e909ce4846c769d353f7979d11ac25516b6"
WMN_CATEGORIES = ("social", "coding", "gaming", "blog", "music", "images", "video")


def select_sites(dataset, limit=60):
    buckets = {c: [] for c in WMN_CATEGORIES}
    for site in sorted(dataset["sites"], key=lambda s: s["name"].lower()):
        if site.get("cat") in buckets and site.get("valid") is not False and not site.get("post_body") and not site.get("protection") and site.get("uri_check", "").startswith("https://") and "{account}" in site["uri_check"]:
            buckets[site["cat"]].append(site)
    selected = []
    while any(buckets.values()) and len(selected) < limit:
        for bucket in buckets.values():
            if bucket and len(selected) < limit:
                selected.append(bucket.pop(0))
    return selected


def classify_site(site, status, text):
    if status in {401, 403, 429} or status >= 500:
        return "blocked" if status < 500 else "error"
    lower = text.lower()
    if any(marker in lower for marker in ("cf-chl-", "verify you are human", "captcha challenge", "just a moment...")):
        return "blocked"
    positive = status == site["e_code"] and (not site.get("e_string") or site["e_string"] in text)
    negative = status == site["m_code"] and (site["m_string"] in text if site.get("m_string") else site["m_code"] != site["e_code"])
    if positive and not negative:
        return "found"
    if negative and not positive:
        return "not_found"
    return "unknown"


def whatsmyname(username):
    import httpx
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import quote
    dataset = json.loads(Path("/opt/wmn/wmn-data.json").read_text())
    sites = select_sites(dataset)
    def check(site):
        account = username
        for char in site.get("strip_bad_char", ""):
            account = account.replace(char, "")
        url = site["uri_check"].replace("{account}", quote(account, safe=""))
        row = {"name": site["name"], "category": site["cat"], "url": site.get("uri_pretty", site["uri_check"]).replace("{account}", quote(account, safe="")), "check_url": url}
        try:
            with httpx.Client(timeout=6, follow_redirects=False, trust_env=False) as client:
                with client.stream("GET", url, headers={"User-Agent": "ChimeraOSINT/0.4 (WhatsMyName dataset consumer)", **site.get("headers", {})}) as r:
                    content = bytearray()
                    for chunk in r.iter_bytes():
                        content.extend(chunk)
                        if len(content) > 1_000_000:
                            return {**row, "status": "unknown", "error": "response_too_large"}
                    text = content.decode(r.encoding or "utf-8", errors="replace")
                    return {**row, "status": classify_site(site, r.status_code, text), "http_status": r.status_code}
        except httpx.TimeoutException:
            return {**row, "status": "timeout"}
        except (httpx.HTTPError, ValueError):
            return {**row, "status": "error"}
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(check, sites))
    return {"checks": rows, "dataset_revision": WMN_REVISION, "license": dataset["license"], "source": "https://github.com/WebBreacher/WhatsMyName", "checked": len(rows), "dataset_total": len(dataset["sites"]), "categories": WMN_CATEGORIES}


def phone_evidence(name, response):
    """Upstream Instagram treats almost any JSON as positive; require explicit evidence."""
    if response is None or response.status_code != 200:
        return None
    try:
        data = response.json()
    except ValueError:
        data = {}
    if name == "instagram":
        if data.get("message") == "No users found":
            return False
        users = data.get("users", [])
        if isinstance(data.get("user"), dict):
            users = [data["user"]]
        return True if isinstance(users, list) and any(isinstance(u, dict) and u.get("username") and (u.get("pk") or u.get("user_id")) for u in users) else None
    if name == "snapchat":
        return {"TAKEN_NUMBER": True, "OK": False}.get(data.get("status_code"))
    text = response.text.lower()
    if "captcha" in text or "robot check" in text:
        return None
    if 'id="auth-password-missing-alert"' in text:
        return True
    if "we cannot find an account with that" in text:
        return False
    return None


async def ignorant(number):
    import httpx
    import trio
    import phonenumbers
    from ignorant.modules.social_media.instagram import instagram
    from ignorant.modules.social_media.snapchat import snapchat
    from ignorant.modules.shopping.amazon import amazon
    parsed = phonenumbers.parse(number, None)
    phone = phonenumbers.national_significant_number(parsed)
    country = str(parsed.country_code)
    results = []
    async def check(function):
        captured = []
        async def capture(response):
            await response.aread()
            captured.append(response)
        rows = []
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True, trust_env=False, event_hooks={"response": [capture]}) as client:
                with trio.fail_after(18):
                    await function(phone, country, client, rows)
            evidence = phone_evidence(function.__name__, captured[-1] if captured else None)
            upstream = rows[0] if rows else {}
            results.append({"name": function.__name__, "domain": upstream.get("domain"), "exists": evidence, "status": "unknown" if evidence is None else "found" if evidence else "not_found", "upstream": upstream, **({"error": "ambiguous_or_blocked_response"} if evidence is None else {})})
        except Exception:
            results.append({"name": function.__name__, "exists": None, "status": "error", "error": "timeout_or_source_error"})
    async with trio.open_nursery() as nursery:
        for function in (instagram, snapchat, amazon):
            nursery.start_soon(check, function)
    return sorted(results, key=lambda row: row["name"])


if __name__ == "__main__":
    tool, value, destination = sys.argv[1:]
    if tool == "ignorant":
        import trio
        result = trio.run(ignorant, value)
    else:
        result = whatsmyname(value)
    Path(destination).write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
