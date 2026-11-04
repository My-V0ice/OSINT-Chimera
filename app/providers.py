import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
from urllib.parse import quote

import httpx

from app.catalog import CATALOG


class ProviderError(Exception):
    def __init__(self, status, message, data=None):
        self.status, self.message = status, message
        self.data = data
        super().__init__(message)


def base58check(value):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for c in value:
        if c not in alphabet:
            raise ValueError("Недопустимый символ адреса.")
        number = number * 58 + alphabet.index(c)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(value) - len(value.lstrip("1"))) + raw
    if len(raw) < 5 or hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] != raw[-4:]:
        raise ValueError("Некорректная контрольная сумма адреса.")
    return raw[:-4]


def valid_bech32(value):
    if value.lower() != value and value.upper() != value:
        return False
    v = value.lower()
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if not v.startswith("bc1") or len(v) > 90:
        return False
    try:
        data = [charset.index(c) for c in v[3:]]
    except ValueError:
        return False
    chk = 1
    for d in [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"] + data:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ d
        for i, g in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            if (top >> i) & 1:
                chk ^= g
    return len(data) >= 7 and data[0] <= 16 and chk == (1 if data[0] == 0 else 0x2bc830a3)


def domain_name(value):
    try:
        value = value.rstrip(".").encode("idna").decode().lower()
    except UnicodeError:
        raise ValueError("Некорректный домен.")
    if len(value) > 253 or "." not in value or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")):
        raise ValueError("Введите домен без протокола, пути и порта.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("Для IP-адреса выберите тип IP.")


def validate_target(kind, value):
    value = value.strip()
    if not value or len(value) > 254 or any(ord(c) < 32 for c in value):
        raise ValueError("Введите корректный поисковый запрос до 254 символов.")
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Некорректный IPv4 или IPv6.")
        if not ip.is_global:
            raise ValueError("Для внешнего OSINT-поиска нужен публичный IP-адрес.")
        return str(ip)
    if kind == "domain":
        return domain_name(value)
    if kind == "email":
        if not re.fullmatch(r"[^\s@<>]{1,64}@[^\s@<>]+", value):
            raise ValueError("Некорректный email.")
        local, domain = value.rsplit("@", 1)
        return local + "@" + domain_name(domain)
    if kind == "phone":
        import phonenumbers
        try:
            number = phonenumbers.parse(value, None)
        except phonenumbers.NumberParseException:
            raise ValueError("Введите телефон с кодом страны, начиная с +.")
        if not value.startswith("+") or not phonenumbers.is_possible_number(number):
            raise ValueError("Номер должен содержать +, код страны и допустимое число цифр.")
        return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)
    if kind == "username" and not re.fullmatch(r"[\w.][\w.\-]{0,63}", value):
        raise ValueError("Ник: до 64 букв, цифр, точек, дефисов или подчёркиваний.")
    if kind == "person" and (len(value) < 2 or value.startswith("-")):
        raise ValueError("Введите имя или ФИО.")
    if kind == "evm":
        if not re.fullmatch(r"0x[a-fA-F0-9]{40}", value):
            raise ValueError("Ethereum-адрес: 0x и 40 шестнадцатеричных символов.")
        return value.lower()
    if kind == "tron":
        if not re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", value) or base58check(value)[0] != 0x41:
            raise ValueError("Некорректный TRON-адрес.")
    if kind == "btc":
        if value.lower().startswith("bc1"):
            if not valid_bech32(value):
                raise ValueError("Некорректный Bitcoin Bech32-адрес.")
            value = value.lower()
        else:
            payload = base58check(value)
            if len(payload) != 21 or payload[0] not in {0, 5}:
                raise ValueError("Введите адрес Bitcoin mainnet.")
    return value


def output(raw, summary=None, entities=None, notes=None, partial=False):
    return {"raw": raw, "summary": summary or {}, "entities": entities or [], "notes": notes or [], "partial": partial}


def entity(kind, value, relation, url="", **attrs):
    return {"type": kind, "value": str(value), "relation": relation, "source_url": url, "attributes": attrs}


class Providers:
    def __init__(self, store):
        self.store = store

    def fetch(self, id, url, params=None, headers=None):
        tool = CATALOG[id]
        self.store.reserve(tool)
        try:
            with httpx.Client(timeout=httpx.Timeout(30, connect=10), follow_redirects=False, trust_env=False) as client:
                with client.stream("GET", url, params=params, headers={"User-Agent": "ChimeraOSINT/1.0 (local research application)", **(headers or {})}) as r:
                    self.store.feedback(id, r.headers, r.status_code == 429 or r.status_code == 403 and r.headers.get("x-ratelimit-remaining") == "0")
                    if r.status_code == 403 and r.headers.get("x-ratelimit-remaining") == "0":
                        raise ProviderError("rate_limited", "Источник исчерпал квоту. Дождитесь сброса лимита.")
                    if r.status_code in {401, 403}:
                        raise ProviderError("auth_error" if tool.key or tool.optional_key else "blocked", "Источник отклонил авторизацию или доступ.")
                    if r.status_code == 429:
                        raise ProviderError("rate_limited", "Источник ограничил запросы. Повторите после сброса лимита.")
                    if r.status_code == 404:
                        raise ProviderError("not_found", "Источник не содержит записи по этому объекту.")
                    if r.status_code >= 300:
                        raise ProviderError("source_error", f"Источник ответил HTTP {r.status_code}.")
                    chunks, size = [], 0
                    for chunk in r.iter_bytes():
                        size += len(chunk)
                        if size > 8_000_000:
                            raise ProviderError("source_error", "Ответ источника превысил 8 МБ.")
                        chunks.append(chunk)
                    try:
                        return json.loads(b"".join(chunks))
                    except (ValueError, UnicodeError):
                        raise ProviderError("source_error", "Источник вернул ответ не в формате JSON.")
        except httpx.TimeoutException:
            raise ProviderError("timeout", "Источник не ответил за отведённое время.")
        except httpx.HTTPError:
            raise ProviderError("network_error", "Не удалось связаться с источником.")

    def run(self, id, kind, value, options=None):
        tool = CATALOG[id]
        if not self.store.config(id)["enabled"]:
            raise ProviderError("disabled", "Инструмент отключён в настройках.")
        if tool.key and not self.store.key(id):
            raise ProviderError("requires_key", "Добавьте API-ключ в настройках интеграций.")
        if id in {'blockscout', 'graphsense', 'ethereumetl'} or options is not None and id in {'esplora', 'trongrid'}:
            from app.crypto import investigate
            return investigate(self, id, kind, value, options or {})
        if tool.runner:
            return self.runner(tool, kind, value)
        return getattr(self, id)(kind, value)

    def ipinfo(self, kind, value):
        raw = self.fetch("ipinfo", f"https://api.ipinfo.io/lite/{quote(value, safe='')}", headers={"Authorization": "Bearer " + self.store.key("ipinfo")})
        entities = []
        if raw.get("country"):
            entities.append(entity("country", raw["country"], "страна по IP", "https://ipinfo.io", approximate=True))
        if raw.get("asn"):
            entities.append(entity("asn", raw["asn"], "автономная система", "https://ipinfo.io", organization=raw.get("as_name")))
        return output(raw, {k: raw[k] for k in ("country", "continent", "asn", "as_name", "as_domain") if k in raw}, entities, ["IP address data powered by IPinfo. Lite не содержит города и координат."])

    def keybase(self, kind, value):
        params = {'usernames' if kind == 'username' else 'domain': value, 'fields': 'basics,profile,proofs_summary,pictures,public_keys'}
        raw = self.fetch('keybase', 'https://keybase.io/_/api/1.0/user/lookup.json', params)
        if not isinstance(raw, dict) or raw.get('status', {}).get('code') != 0 or not isinstance(raw.get('them'), list):
            raise ProviderError('source_error', 'Keybase вернул ошибку или неподдерживаемый ответ.')
        rows = [r for r in raw['them'] if isinstance(r, dict) and r.get('basics', {}).get('username')]
        entities = []
        for row in rows:
            url = 'https://keybase.io/' + quote(row['basics']['username'], safe='')
            entities.append(entity('profile', url, 'публичный профиль Keybase', url))
            for proof in row.get('proofs_summary', {}).get('all', []):
                url = proof.get('service_url')
                if isinstance(url, str) and url.startswith(('http://', 'https://')):
                    entities.append(entity('profile', url, 'опубликованная связь Keybase', url, service=proof.get('proof_type'), independently_verified=False))
        return output(raw, {'Профилей Keybase': len(rows), 'Публичных связей': max(0, len(entities)-len(rows))}, entities, ['Доказательства приведены по данным сервера Keybase; независимая криптографическая проверка не выполнялась.'])

    def proxycheck(self, kind, value):
        params = {'ver': '2026-06-24'}
        key = self.store.key('proxycheck')
        if key:
            params['key'] = key
        raw = self.fetch('proxycheck', 'https://proxycheck.io/v3/' + quote(value, safe=''), params)
        if not isinstance(raw, dict):
            raise ProviderError('source_error', 'ProxyCheck вернул неподдерживаемый формат ответа.')
        status = raw.get('status')
        if status not in {'ok', 'warning'}:
            message = str(raw.get('message', '')).lower()
            if any(word in message for word in ('limit', 'exhaust', 'allowance', 'queries remaining')):
                self.store.feedback('proxycheck', {}, True)
                raise ProviderError('rate_limited', 'ProxyCheck ограничил запросы. Проверьте остаток квоты и срок её сброса.')
            if 'key' in message and any(word in message for word in ('invalid', 'disabled', 'missing')):
                raise ProviderError('auth_error', 'ProxyCheck отклонил API-ключ. Проверьте его в настройках.')
            raise ProviderError('blocked' if status == 'denied' else 'source_error', 'ProxyCheck отклонил запрос или не завершил проверку IP.')
        record = None
        for address, candidate in raw.items():
            try:
                if ipaddress.ip_address(address) == ipaddress.ip_address(value):
                    record = candidate
                    break
            except ValueError:
                continue
        detections = record.get('detections') if isinstance(record, dict) else None
        if not isinstance(detections, dict) or any(not isinstance(detections.get(flag), bool) for flag in ('proxy', 'vpn')):
            raise ProviderError('source_error', 'ProxyCheck не вернул корректные признаки proxy/VPN для запрошенного IP.')
        summary = {'Proxy': detections['proxy'], 'VPN': detections['vpn']}
        for field, label in (('tor', 'Tor'), ('hosting', 'Хостинг'), ('anonymous', 'Анонимный выход'), ('risk', 'Риск источника, 0–100'), ('confidence', 'Уверенность источника, 0–100')):
            if field in detections:
                summary[label] = detections[field]
        network = record.get('network') or {}
        summary.update({'Провайдер': network.get('provider'), 'ASN': network.get('asn')})
        notes = ['Признаки и оценки предоставлены ProxyCheck.io; они не гарантируют фактическое использование VPN или proxy. Анонимность, хостинг и VPN показаны раздельно.']
        if status == 'warning':
            notes.append('Предупреждение ProxyCheck: ' + str(raw.get('message') or 'Сервис принял запрос с предупреждением.'))
        return {**output(raw, summary, notes=notes), 'processed_data': record}

    def emailrep(self, kind, value):
        raw = self.fetch('emailrep', 'https://emailrep.io/' + quote(value, safe=''), headers={'Key': self.store.key('emailrep'), 'Accept': 'application/json'})
        if not isinstance(raw, dict) or raw.get('error') or not raw.get('email') or not isinstance(raw.get('details'), dict):
            raise ProviderError('source_error', 'EmailRep отклонил запрос или вернул неподдерживаемый ответ.')
        profiles = raw['details'].get('profiles', [])
        entities = [entity('service', name, 'признак профиля по данным EmailRep', confirmed_owner=False) for name in profiles if isinstance(name, str)]
        return output(raw, {'Репутация': raw.get('reputation'), 'Подозрительный': raw.get('suspicious'), 'Источников репутации': raw.get('references'), 'Признаков профилей': len(entities)}, entities, ['Ответ включает оценку репутации и свойства домена даже при отсутствии профилей. Это данные проверки, а не подтверждённые аккаунты.'])

    def github(self, kind, value):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        key = self.store.key("github")
        if key:
            headers["Authorization"] = "Bearer " + key
        if kind == "username":
            raw = self.fetch("github", "https://api.github.com/users/" + quote(value, safe=""), headers=headers)
            if not isinstance(raw, dict) or not raw.get("login") or not raw.get("html_url"):
                raise ProviderError("source_error", "GitHub вернул неподдерживаемый формат профиля.")
            rows = [raw]
            summary = {"Аккаунт": raw["login"], "Имя": raw.get("name"), "Публичные репозитории": raw.get("public_repos"), "Подписчики": raw.get("followers")}
        else:
            # Quote a literal search term; no caller-controlled qualifiers.
            term = value.replace('"', ' ').replace('\\', ' ')
            qualifier = "email" if kind == "email" else "fullname"
            raw = self.fetch("github", "https://api.github.com/search/users", {"q": f'"{term}" in:{qualifier} type:user', "per_page": 30}, headers)
            if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
                raise ProviderError("source_error", "GitHub вернул неподдерживаемый формат поиска.")
            rows = raw["items"]
            summary = {"Кандидатов всего": raw.get("total_count"), "Показано": len(rows)}
        notes = ["Публичные сведения GitHub. Совпадение нику, имени или email не подтверждает владельца."]
        if kind == "email":
            notes.append("Поиск охватывает только публично индексируемый email; скрытый email недоступен.")
        if raw.get("total_count", 0) > len(rows):
            notes.append("Показаны первые 30 кандидатов; остальные результаты не запрашивались.")
        if raw.get("incomplete_results"):
            notes.append("GitHub сообщил о неполном поисковом ответе.")
        return output(raw, summary, [entity("profile", r["html_url"], "кандидат GitHub", r["html_url"], username=r.get("login"), confirmed_owner=False) for r in rows if r.get("html_url")], notes, bool(raw.get("incomplete_results")))

    def gravatar(self, kind, value):
        digest = hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()
        raw = self.fetch("gravatar", "https://api.gravatar.com/v3/profiles/" + digest, headers={"Authorization": "Bearer " + self.store.key("gravatar")})
        if not isinstance(raw, dict) or not raw.get("profile_url"):
            raise ProviderError("source_error", "Gravatar вернул неподдерживаемый формат профиля.")
        entities = [entity("profile", raw["profile_url"], "профиль Gravatar по хешу email", raw["profile_url"])]
        for account in raw.get("verified_accounts", []):
            if isinstance(account, dict) and account.get("url"):
                entities.append(entity("profile", account["url"], "связанный аккаунт из Gravatar", account["url"], service=account.get("service_label"), verified=account.get("is_verified")))
        return output(raw, {"Имя": raw.get("display_name"), "Профиль": raw.get("profile_url"), "Связанных аккаунтов": len(entities) - 1}, entities, ["В Gravatar передаётся SHA-256 нормализованного email. Связи отражают данные источника; дополнительные email могут не находиться."])

    def abuseipdb(self, kind, value):
        raw = self.fetch("abuseipdb", "https://api.abuseipdb.com/api/v2/check", {"ipAddress": value, "maxAgeInDays": 90, "verbose": ""}, {"Key": self.store.key("abuseipdb"), "Accept": "application/json"})
        d = raw.get("data", {})
        return output(raw, {"Оценка жалоб": d.get("abuseConfidenceScore"), "Жалоб за 90 дней": d.get("totalReports"), "ISP": d.get("isp"), "Последняя жалоба": d.get("lastReportedAt")}, notes=["Оценка жалоб — мнение источника, а не подтверждение вредоносности."])

    def internetdb(self, kind, value):
        raw = self.fetch("internetdb", "https://internetdb.shodan.io/" + quote(value, safe=""))
        entities = [entity("domain", x, "имя хоста", "https://internetdb.shodan.io/") for x in raw.get("hostnames", [])]
        entities += [entity("port", x, "порт по данным Shodan") for x in raw.get("ports", [])]
        return output(raw, {"Порты": raw.get("ports", []), "Возможные CVE": raw.get("vulns", []), "Метки": raw.get("tags", [])}, entities, ["InternetDB: бесплатно для некоммерческого использования. Возможные CVE определены по метаданным."])

    def geolite(self, kind, value):
        import geoip2.database
        root = Path(os.getenv("CHIMERA_GEOLITE", "geolite"))
        raw, entities = {}, []
        for name in ("GeoLite2-City.mmdb", "GeoLite2-Country.mmdb", "GeoLite2-ASN.mmdb"):
            file = root / name
            if not file.exists():
                continue
            try:
                with geoip2.database.Reader(str(file)) as reader:
                    record = reader.asn(value) if "ASN" in name else reader.city(value) if "City" in name else reader.country(value)
                    raw[name] = record.to_dict()
            except geoip2.errors.AddressNotFoundError:
                raw[name] = {"not_found": True}
        if not raw:
            raise ProviderError("requires_database", "Поместите GeoLite2-City.mmdb / Country.mmdb / ASN.mmdb в папку geolite.")
        summary = {}
        for name, data in raw.items():
            if data.get("country"):
                country = data["country"].get("names", {}).get("ru") or data["country"].get("names", {}).get("en")
                if country:
                    summary["Страна"] = country
                    entities.append(entity("country", country, "страна по GeoLite", approximate=True))
            if data.get("city"):
                summary["Город (приблизительно)"] = data["city"].get("names", {}).get("ru") or data["city"].get("names", {}).get("en")
            if data.get("location"):
                summary["Геолокация"] = data["location"]
            if data.get("autonomous_system_number"):
                summary["ASN"] = data["autonomous_system_number"]
                entities.append(entity("asn", "AS" + str(data["autonomous_system_number"]), "автономная система", organization=data.get("autonomous_system_organization")))
        return output(raw, summary, entities, ["GeoLite by MaxMind. Геолокация приблизительная и не определяет адрес дома."])

    def ipwhois(self, kind, value):
        from ipwhois import IPWhois
        self.store.reserve(CATALOG["ipwhois"])
        try:
            raw = IPWhois(value, timeout=15).lookup_rdap(depth=0, retry_count=0)
        except Exception:
            raise ProviderError("source_error", "RDAP-запрос не выполнен: проверьте сеть или ограничение реестра.")
        net = raw.get("network") or {}
        ents = [entity("network", net["cidr"], "входит в диапазон")] if net.get("cidr") else []
        if raw.get("asn"):
            ents.append(entity("asn", "AS" + raw["asn"], "автономная система", organization=raw.get("asn_description")))
        return output(raw, {"Диапазон": net.get("cidr"), "Имя сети": net.get("name"), "ASN": raw.get("asn"), "Описание": raw.get("asn_description"), "Реестр": raw.get("asn_registry")}, ents)

    def dns(self, kind, value):
        import dns.resolver
        import dns.reversename
        self.store.reserve(CATALOG["dns"])
        target = value.rsplit("@", 1)[-1] if kind == "email" else value
        resolver = dns.resolver.Resolver()
        resolver.lifetime, resolver.timeout = 6, 3
        raw, notes, entities, failures = {}, [], [], 0
        types = ["PTR"] if kind == "ip" else ["A", "AAAA", "MX", "NS", "TXT"]
        for record in types:
            try:
                name = dns.reversename.from_address(target) if kind == "ip" else target
                result = resolver.resolve(name, record)
                raw[record] = {"values": [r.to_text() for r in result], "ttl": result.rrset.ttl}
                for r in result:
                    if record in {"A", "AAAA"}:
                        entities.append(entity("ip", str(r), "DNS " + record))
                    elif record in {"MX", "NS", "PTR"}:
                        entities.append(entity("domain", str(r.exchange if record == "MX" else r.target).rstrip("."), "DNS " + record))
            except dns.resolver.NXDOMAIN:
                return output({"status": "NXDOMAIN", "domain": target}, {"DNS": "Домен не существует по ответу резолвера"})
            except dns.resolver.NoAnswer:
                raw[record] = {"values": [], "status": "no_answer"}
            except Exception:
                raw[record] = {"status": "error"}
                notes.append(f"{record}: ошибка резолвера или таймаут.")
                failures += 1
        if failures == len(types):
            raise ProviderError("network_error", "DNS-резолвер не ответил на запросы.")
        if kind == "email":
            notes.append("DNS исследует домен и не подтверждает существование ящика.")
        return output(raw, {k: v.get("values", v["status"] if "status" in v else []) for k, v in raw.items()}, entities, notes, bool(failures))

    def phonenumbers(self, kind, value):
        import phonenumbers as p
        from phonenumbers import carrier, geocoder, timezone
        number = p.parse(value, None)
        raw = {"e164": p.format_number(number, p.PhoneNumberFormat.E164), "international": p.format_number(number, p.PhoneNumberFormat.INTERNATIONAL), "valid_pattern": p.is_valid_number(number), "possible": p.is_possible_number(number), "country_code": number.country_code, "region_code": p.region_code_for_number(number), "description": geocoder.description_for_number(number, "ru"), "original_carrier": carrier.name_for_number(number, "ru"), "time_zones": list(timezone.time_zones_for_number(number)), "number_type": p.number_type(number)}
        ents = [entity("country", raw["region_code"], "страна нумерации")] if raw["region_code"] else []
        return output(raw, {"Номер": raw["international"], "Шаблон действителен": raw["valid_pattern"], "Регион нумерации": raw["description"], "Исходный оператор": raw["original_carrier"], "Часовые пояса": raw["time_zones"]}, ents, ["Локальные метаданные. Активность SIM, владелец и текущее местоположение не устанавливаются."])

    def wikidata(self, kind, value):
        raw = self.fetch("wikidata", "https://www.wikidata.org/w/api.php", {"action": "wbsearchentities", "search": value, "language": "ru", "uselang": "ru", "limit": 10, "format": "json", "type": "item"})
        if raw.get("error"):
            raise ProviderError("source_error", "Wikidata вернула ошибку поиска.")
        ents = [entity("candidate", x["id"], "кандидат по имени", "https://www.wikidata.org/wiki/" + x["id"], label=x.get("label"), description=x.get("description")) for x in raw.get("search", [])]
        return output(raw, {"Кандидаты": [{"id": x["id"], "имя": x.get("label"), "описание": x.get("description")} for x in raw.get("search", [])]}, ents, ["Поиск возвращает элементы Wikidata, включая одноимённые объекты. Принадлежность человеку не подтверждена."])

    def openalex(self, kind, value):
        params = {"search": value, "per-page": 10}
        if self.store.key("openalex"):
            params["api_key"] = self.store.key("openalex")
        raw = self.fetch("openalex", "https://api.openalex.org/authors", params)
        ents = [entity("candidate", x["id"], "автор — кандидат по имени", x["id"], label=x.get("display_name"), orcid=x.get("orcid"), institutions=x.get("last_known_institutions")) for x in raw.get("results", [])]
        return output(raw, {"Найдено авторов": raw.get("meta", {}).get("count"), "Показано": len(ents)}, ents, ["Показаны первые 10 кандидатов в научной среде; совпадение имени не подтверждает личность."])

    def multi(self, id, calls):
        raw, failures = {}, []
        for name, url, params, headers in calls:
            try:
                raw[name] = self.fetch(id, url, params, headers)
            except ProviderError as e:
                raw[name] = {"error": e.status, "message": e.message}
                failures.append(e)
        if len(failures) == len(calls):
            raise failures[0]
        return raw, [e.message for e in failures], bool(failures)

    def esplora(self, kind, value):
        base = os.getenv("ESPLORA_URL", "https://blockstream.info/api").rstrip("/")
        raw, notes, partial = self.multi("esplora", [("address", base + "/address/" + value, None, None), ("transactions", base + "/address/" + value + "/txs", None, None)])
        stats = raw.get("address", {}).get("chain_stats", {})
        entities = []
        txs = raw.get("transactions", [])
        if isinstance(txs, list):
            for tx in txs:
                entities.append(entity("transaction", "btc:" + tx["txid"], "транзакция адреса", "https://blockstream.info/tx/" + tx["txid"], network="btc"))
        return output(raw, {"Баланс подтверждённый, sat": stats.get("funded_txo_sum", 0) - stats.get("spent_txo_sum", 0) if stats else None, "Транзакций подтверждено": stats.get("tx_count"), "Показано транзакций": len(entities)}, entities, notes + ["Ограниченная первая страница; владельцы адресов не устанавливаются."], partial)

    def etherscan(self, kind, value):
        base = {"chainid": "1", "module": "account", "address": value, "apikey": self.store.key("etherscan")}
        raw, notes, partial = self.multi("etherscan", [(action, "https://api.etherscan.io/v2/api", {**base, "action": action, **({"tag": "latest"} if action == "balance" else {"page": 1, "offset": 25, "sort": "desc"})}, None) for action in ("balance", "txlist", "tokentx")])
        successful = 0
        for action, response in raw.items():
            if response.get("status") == "0" and not (isinstance(response.get("result"), list) and not response["result"] and "no transactions" in str(response.get("message", "")).lower()):
                message = str(response.get("result", "" )).lower()
                status = "auth_error" if "key" in message else "rate_limited" if "rate limit" in message else "source_error"
                if status == "rate_limited":
                    self.store.feedback("etherscan", {}, True)
                response.clear()
                response.update(error=status, message="Etherscan отклонил операцию; проверьте ключ, тариф и лимит.")
                partial = True
                notes.append(action + ": " + response["message"])
            elif not response.get("error"):
                successful += 1
        if not successful:
            error = next(iter(raw.values()))
            raise ProviderError(error.get("error", "source_error"), error.get("message", "Etherscan отклонил запрос."))
        entities = []
        for action in ("txlist", "tokentx"):
            txs = raw.get(action, {}).get("result", [])
            if isinstance(txs, list):
                for tx in txs:
                    for k in ("from", "to"):
                        address = tx.get(k, "").lower()
                        if address and address != value:
                            entities.append(entity("evm", address, "контрагент транзакции", "https://etherscan.io/tx/" + tx.get("hash", ""), transaction=tx.get("hash"), network="ethereum"))
        return output(raw, {"Сеть": "Ethereum mainnet", "Баланс, wei": raw.get("balance", {}).get("result"), "Контрагенты на странице": len({x["value"] for x in entities})}, entities, notes + ["Первые 25 операций каждого вида; это не полная история. Совместное участие в транзакции не доказывает общего владельца."], partial)

    def trongrid(self, kind, value):
        headers = {"TRON-PRO-API-KEY": self.store.key("trongrid")}
        raw, notes, partial = self.multi("trongrid", [("account", "https://api.trongrid.io/v1/accounts/" + value, None, headers), ("trc20", "https://api.trongrid.io/v1/accounts/" + value + "/transactions/trc20", {"limit": 25, "only_confirmed": "true"}, headers)])
        successes = 0
        for operation, response in raw.items():
            if response.get("success") is False:
                response.clear()
                response.update(error="source_error", message="TronGrid отклонил операцию; проверьте ключ и лимиты.")
                notes.append(operation + ": " + response["message"])
                partial = True
            elif not response.get("error"):
                successes += 1
        if not successes:
            raise ProviderError("source_error", "TronGrid не выполнил операции; проверьте ключ и лимиты.")
        entities = []
        for tx in raw.get("trc20", {}).get("data", []):
            for k in ("from", "to"):
                if tx.get(k) and tx[k] != value:
                    entities.append(entity("tron", tx[k], "контрагент TRC-20", "https://tronscan.org/#/transaction/" + tx.get("transaction_id", ""), transaction=tx.get("transaction_id")))
        accounts = raw.get("account", {}).get("data", [])
        return output(raw, {"Баланс TRX, sun": accounts[0].get("balance", 0) if accounts else None, "TRC-20 на странице": len(raw.get("trc20", {}).get("data", []))}, entities, notes + ["Первые 25 подтверждённых TRC-20 операций; это не полная история."], partial)

    def runner(self, tool, kind, value):
        url = os.getenv(tool.runner, "").rstrip("/")
        if not url:
            raise ProviderError("requires_runner", "Запустите контейнеры сборщиков: docker compose --profile tools up -d --build.")
        try:
            with httpx.Client(timeout=200, trust_env=False) as client:
                response = client.post(url + "/run", json={"tool": tool.id, "kind": kind, "value": value})
            if response.status_code != 200:
                raise ProviderError("source_error", "Контейнер сборщика отклонил задание.")
            result = response.json()
            if result.get("error"):
                raise ProviderError(result["error"], result.get("message", "Ошибка сборщика."), result.get("raw"))
            if tool.id == "phoneinfoga":
                from app.phoneinfoga import normalize
                result = normalize(result)
            return result
        except (httpx.HTTPError, ValueError):
            raise ProviderError("runner_unavailable", "Контейнер сборщика недоступен или превысил время ожидания.")
