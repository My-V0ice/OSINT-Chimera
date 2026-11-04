from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class Tool:
    id: str
    name: str
    types: tuple[str, ...]
    mode: str
    description: str
    limit: str
    source: str
    key: bool = False
    optional_key: bool = False
    runner: str = ""
    daily: int = 0
    interval: float = 0
    note: str = ""
    connection: bool = False


TOOLS = [
    Tool('blockscout', 'Blockscout Transfers', ('evm',), 'api', 'Переводы EVM: монеты, токены и внутренние операции', 'Free: 100 000 кредитов/сутки, 5 запросов/с; нужен бесплатный ключ; до 3 страниц за запуск', 'https://docs.blockscout.com/devs/blockscout-api', key=True, interval=.25, note='Ethereum, Base, Optimism и Scroll. Кредиты не равны числу запросов. Используется Universal API; принадлежность адресов не устанавливается.'),
    Tool('graphsense', 'GraphSense', ('btc', 'evm', 'tron'), 'api', 'История адреса из собственного GraphSense REST API', 'Открытый MIT-стек; собственный индексатор и Cassandra; квота зависит от сервера', 'https://graphsense.org/documentation', optional_key=True, connection=True, interval=.2, note='Укажите URL готового GraphSense API в настройках. Полный индекс блокчейна автоматически не загружается. Для BTC изменение баланса не приписывается конкретному контрагенту.'),
    Tool('ethereumetl', 'Ethereum ETL', ('evm',), 'network', 'Экспорт переводов адреса в диапазоне блоков через собственный RPC', 'Открытая CLI; до 20 блоков за запуск, 120 секунд; нужен RPC и сборщик профиля crypto', 'https://github.com/blockchain-etl/ethereum-etl', runner='ETHEREUM_ETL_URL', connection=True, note='Монеты, ERC-20/721 либо Parity-style traces. RPC должен поддерживать выбранный метод и сеть. Стоимость запросов зависит от RPC-провайдера.'),
    Tool('keybase', 'Keybase', ('username', 'domain'), 'api', 'Публичный профиль Keybase и опубликованные связи с аккаунтами', 'Бесплатно, без ключа; фиксированная квота не опубликована; интервал 1 секунда', 'https://keybase.io/docs/api/1.0/call/user/lookup', interval=1, note='Публичный API открытого проекта Keybase. Для ника ищется точное имя Keybase; криптографическая проверка доказательств клиентом здесь не выполняется.'),
    Tool('emailrep', 'EmailRep', ('email',), 'api', 'Репутация email, признаки публичных профилей и сведения источника', 'Community: бесплатно 250 запросов/месяц, максимум 10/сутки; нужен ключ', 'https://github.com/sublime-security/emailrep.io', key=True, daily=10, interval=1, note='Открытая спецификация и клиент, внешняя база сервиса. Репутация и признаки профилей не подтверждают принадлежность аккаунтов. Месячный остаток определяется источником.'),
    Tool('pywhat', 'PyWhat', ('text',), 'local', 'Распознавание формата строки: email, адреса, хеши и другие идентификаторы', 'Бесплатно, локально, без внешних запросов и ключей; строка до 254 символов', 'https://github.com/bee-san/pyWhat', runner='ACCOUNTS_URL', note='Предположения по формату строки, а не поиск аккаунтов. Файлы не читаются, найденные ключи не проверяются во внешних сервисах.'),
    Tool("geolite", "MaxMind GeoLite", ("ip",), "local", "Приблизительная геолокация и ASN из локальных MMDB", "Без квоты на чтение локальных баз", "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/"),
    Tool("ipwhois", "ipwhois / RDAP", ("ip",), "network", "Диапазон адресов, организация и регистрационные данные", "Ограничения серверов реестров", "https://github.com/secynic/ipwhois", interval=1),
    Tool("ipinfo", "IPinfo Lite", ("ip",), "api", "Страна, континент и автономная система", "Lite: без месячной квоты; требуется атрибуция", "https://ipinfo.io", key=True, interval=.15),
    Tool("abuseipdb", "AbuseIPDB", ("ip",), "api", "Репутация IP и сведения о жалобах", "Free: 1 000 проверок / сутки", "https://docs.abuseipdb.com/", key=True, daily=1000, interval=1),
    Tool("internetdb", "Shodan InternetDB", ("ip",), "api", "Известные порты, хосты, CPE и возможные CVE", "Бесплатно для некоммерческого использования; данные еженедельные", "https://internetdb.shodan.io/", interval=1, note="CVE по метаданным не подтверждает уязвимость узла."),
    Tool('proxycheck', 'ProxyCheck.io', ('ip',), 'api', 'Проверка IP на proxy, VPN, Tor, хостинг и другие признаки анонимности', 'Без ключа 100 проверок/сутки на исходящий IP; бесплатный ключ — 1 000/сутки; лимит контролирует сервис', 'https://proxycheck.io/api/', optional_key=True, interval=1, note='HTTPS API v3, версия 2026-06-24. Признаки и оценки передаются по данным ProxyCheck, без активного подключения к проверяемому IP. Отрицательный ответ — результат проверки, а не отсутствие данных; анонимность не означает автоматически VPN.'),
    Tool("maigret", "Maigret", ("username",), "network", "Поиск публичных профилей и связанных идентификаторов", "Лимиты отдельных сайтов; до 100 сайтов за запуск", "https://github.com/soxoj/maigret", runner="SCANNERS_URL"),
    Tool("sherlock", "Sherlock", ("username",), "network", "Дополнительный поиск аккаунтов по нику", "Лимиты отдельных сайтов; ограниченное время запуска", "https://github.com/sherlock-project/sherlock", runner="SCANNERS_URL"),
    Tool("holehe", "Holehe", ("email",), "network", "Признаки регистрации email на сайтах", "Лимиты отдельных сайтов; ошибки учитываются по модулям", "https://github.com/megadose/holehe", runner="SCANNERS_URL"),
    Tool("socialscan", "Socialscan", ("email", "username"), "network", "Признаки занятости email и ников на платформах", "Бесплатно, без ключа; лимиты и CAPTCHA отдельных платформ; до 160 секунд", "https://github.com/iojw/socialscan", runner="ACCOUNTS_URL", note="Занятый ник может быть зарезервирован или принадлежать удалённому аккаунту; совпадение не подтверждает владельца."),
    Tool("ignorant", "Ignorant", ("phone",), "network", "Признаки использования телефона: Instagram, Snapchat и Amazon", "Бесплатно, без ключа; 3 модуля, до 18 секунд на модуль; возможны блокировки", "https://github.com/megadose/ignorant", runner="ACCOUNTS_URL", note="Экспериментальные модули. Неоднозначные ответы и CAPTCHA считаются ошибками, а не найденными аккаунтами."),
    Tool("whatsmyname", "WhatsMyName", ("username",), "network", "Публичные профили по нику из базы WhatsMyName", "Бесплатно; фиксированный набор до 60 GET-проверок, 4 одновременно, таймаут 6 секунд", "https://github.com/WebBreacher/WhatsMyName", runner="ACCOUNTS_URL", note="Локальный проверяющий модуль Химеры использует закреплённую базу WMN (CC BY-SA 4.0). Проверяются social, coding, gaming, blog, music, images, video; найденный профиль не подтверждает владельца."),
    Tool("github", "GitHub Accounts", ("email", "username", "person"), "api", "Публичный аккаунт по нику; кандидаты по открытому email или имени", "Без ключа 60 запросов/час/IP, поиск 10/мин; с токеном обычно 5 000/час, поиск 30/мин", "https://docs.github.com/en/rest/search/search#search-users", optional_key=True, interval=6.1, note="Для email доступны только индексируемые публичные сведения; первые 30 кандидатов. Токен необязателен, достаточно доступа к публичным данным."),
    Tool("gravatar", "Gravatar Profiles", ("email",), "api", "Публичный профиль и связанные аккаунты по SHA-256 email", "Бесплатный API-ключ: по умолчанию 1 000 запросов/час", "https://docs.gravatar.com/rest/api-data-specifications/", key=True, interval=3.6, note="Используется API v3. Нужен бесплатный ключ Gravatar; скрытые профили и дополнительные email могут не находиться."),
    Tool("theharvester", "theHarvester", ("domain", "email"), "network", "Открытые сведения о домене и организации", "В этой версии: бесключевые crtsh и certspotter", "https://github.com/laramies/theHarvester", runner="HARVESTER_URL", note="Для email исследуется домен, а не принадлежность ящика."),
    Tool("dns", "dnspython", ("domain", "email", "ip"), "network", "DNS: A, AAAA, MX, TXT, NS и PTR", "Ограничения DNS-резолвера", "https://github.com/rthalley/dnspython", interval=.2),
    Tool("phonenumbers", "libphonenumber", ("phone",), "local", "Формат, страна, тип и исходный оператор номера", "Локально, без внешних запросов", "https://github.com/daviddrysdale/python-phonenumbers", note="Не подтверждает активность номера или текущее местоположение."),
    Tool("phoneinfoga", "PhoneInfoga", ("phone",), "network", "Локальный сканер и поисковые зацепки по номеру", "В этой версии: local и googlesearch; без платных сканеров", "https://github.com/sundowndev/phoneinfoga", runner="PHONEINFOGA_URL", note="Экспериментально: upstream не поддерживается."),
    Tool("wikidata", "Wikidata", ("person",), "api", "Публичные персоны и их идентификаторы", "До 10 кандидатов за запрос; лимиты Wikimedia", "https://www.wikidata.org/", interval=1),
    Tool("openalex", "OpenAlex", ("person",), "api", "Авторы научных работ и организации", "Без ключа $0.10/день; бесплатный ключ $1/день; стоимость зависит от операции", "https://help.openalex.org/api/", optional_key=True, interval=.2),
    Tool("spiderfoot", "SpiderFoot OSS", ("ip", "domain", "email", "username", "person", "btc"), "network", "Связи из выбранных бесключевых модулей", "Лимиты модулей; только явно выбранный набор", "https://github.com/smicallef/spiderfoot", runner="SPIDERFOOT_URL", note="Ключевые модули агрегаторов пока не подключены; общие ключи не расходуются ими."),
    Tool("esplora", "Blockstream Esplora", ("btc",), "api", "История Bitcoin, отдельные выходы и их дальнейшее расходование", "Публичный API без гарантированной квоты; 25 транзакций/страница, до 3 страниц и 5 проверок расходований", "https://github.com/Blockstream/esplora/blob/master/API.md", interval=1),
    Tool("etherscan", "Etherscan V2", ("evm",), "api", "Баланс ETH, последние транзакции и ERC-20 переводы", "Free: 3 запроса/с, 100 000/сутки; здесь сеть Ethereum (chainid=1)", "https://docs.etherscan.io/rate-limits", key=True, daily=100000, interval=.35),
    Tool("trongrid", "TronGrid", ("tron",), "api", "История переводов TRX и TRC-20 с пагинацией", "Квота и QPS зависят от аккаунта TronGrid; до 3 страниц по 50 операций", "https://developers.tron.network/reference/rate-limits", key=True, interval=.5),
]
CATALOG = {tool.id: tool for tool in TOOLS}
TYPES = {"ip": "IP-адрес", "domain": "Домен", "username": "Ник", "email": "Email", "phone": "Телефон", "person": "ФИО", "btc": "Bitcoin", "evm": "Ethereum", "tron": "TRON"}


def metadata(tool):
    return {**asdict(tool), "limits_checked": "2026-11-02" if tool.id in {'keybase', 'emailrep', 'pywhat', 'proxycheck', 'blockscout', 'graphsense', 'ethereumetl'} else "2026-10-27", "adapter_version": "1.1" if tool.id == "phoneinfoga" else "1.0"}

TYPES['text'] = 'Строка / идентификатор'
