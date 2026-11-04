# Разработка

Используйте Python 3.12 (как в Docker) и Node.js 24 для тестов интерфейса.
Node.js не нужен для запуска приложения. Установка npm-пакетов не требуется.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
node --check app/static/app.js
node --check app/static/crypto.js
node --check app/static/localcsv.js
node --test tests/*.test.cjs
docker compose --profile tools --profile crypto config --quiet
docker build -t chimera:local .
```

На Windows замените `.venv/bin/python` на `.venv/Scripts/python`.
Если оболочка не раскрывает `*`, перечислите файлы явно:

```sh
node --test tests/ui.test.cjs tests/crypto-ui.test.cjs tests/csv-ui.test.cjs
```

В pull request опишите изменение поведения и выполненные проверки.
Тестовые примеры должны использовать вымышленные данные и подменённые ответы API.
Не прикладывайте ключи, реальные выгрузки CSV, локальные базы и историю исследований.
Настройки ключей выполняются в интерфейсе приложения; `.env` автоматически не загружается при запуске Python.

GitHub Actions запускает Python- и JavaScript-тесты, проверяет Compose, собирает основной
Docker-образ и проверяет его HTTP API. Контейнеры внешних сборщиков и реальные
внешние источники этот workflow не проверяет.
