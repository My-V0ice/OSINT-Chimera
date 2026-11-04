"""Import credentials on stdin. Never echoes values or makes external requests."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.storage import Store
from app.catalog import CATALOG

if __name__ == "__main__":
    payload = json.loads(sys.stdin.readline())
    store = Store()
    for id, key in payload.items():
        tool = CATALOG.get(id)
        if not tool or not (tool.key or tool.optional_key) or not isinstance(key, str) or not key.strip() or len(key) > 512:
            raise SystemExit("Некорректный формат импорта ключей.")
    for id, key in payload.items():
        store.save_key(id, key.strip())
    print(f"Сохранено ключей: {len(payload)}. Значения зашифрованы; сетевые проверки не выполнялись.")
