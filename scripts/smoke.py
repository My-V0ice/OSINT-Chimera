"""Run inside the app container. Reports readiness, never secrets or external target data."""
import json
import os
import httpx

checks = {}
for name in ("SCANNERS_URL", "HARVESTER_URL", "SPIDERFOOT_URL", "PHONEINFOGA_URL"):
    try:
        r = httpx.get(os.environ[name] + "/health", timeout=5, trust_env=False)
        checks[name] = r.json()
    except Exception:
        checks[name] = {"status": "unavailable"}
print(json.dumps(checks, ensure_ascii=False, indent=2))
