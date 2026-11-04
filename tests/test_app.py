import json
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from app.catalog import CATALOG
from app.main import create_app
from app.providers import ProviderError, Providers, output, entity, validate_target
from app.service import Engine
from app.storage import Store, now


class AppTests(unittest.TestCase):
    def setUp(self):
        test_root = Path(__file__).resolve().parents[1] / ".local" / "tests"
        test_root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=test_root)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / "data", Path(self.tmp.name) / "secrets")
        self.client = TestClient(create_app(self.store))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.csrf = self.client.get("/api/bootstrap").json()["csrf"]
        self.headers = {"x-chimera-csrf": self.csrf}

    def wait_job(self, id):
        for _ in range(100):
            job = self.client.get("/api/jobs/" + id).json()
            if job["status"] not in {"queued", "running"}:
                return job
            time.sleep(.02)
        self.fail("Job did not finish")

    def create(self, kind, value, tools):
        return self.client.post("/api/jobs", headers=self.headers, json={"kind": kind, "value": value, "tools": tools})

    def test_clean_boot_and_keyless_local_job(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        catalog = self.client.get("/api/tools").json()
        self.assertEqual(len(catalog), 30)
        self.assertEqual(next(t for t in catalog if t["id"] == "ipinfo")["state"], "requires_key")
        response = self.create("phone", "+12025550123", ["phonenumbers"])
        self.assertEqual(response.status_code, 202)
        job = self.wait_job(response.json()["id"])
        self.assertEqual(job["status"], "completed")
        self.assertEqual(job["runs"][0]["result"]["raw"]["e164"], "+12025550123")
        self.assertTrue(job["graph"]["nodes"])

    def test_missing_credential_blocks_source_without_network(self):
        with patch("app.providers.httpx.Client") as client:
            response = self.create("ip", "8.8.8.8", ["ipinfo"])
            job = self.wait_job(response.json()["id"])
            self.assertEqual(job["runs"][0]["status"], "requires_key")
            client.assert_not_called()

    def test_credentials_encrypted_masked_persistent_replace_delete(self):
        secret = "test-secret-123456789"
        response = self.client.put("/api/tools/ipinfo/key", headers=self.headers, json={"key": secret})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(secret, response.text)
        self.assertTrue(response.json()["has_key"])
        self.assertNotIn(secret.encode(), self.store.path.read_bytes())
        reopened = Store(self.store.root, self.store.secrets)
        self.assertEqual(reopened.key("ipinfo"), secret)
        self.client.put("/api/tools/ipinfo/key", headers=self.headers, json={"key": "replacement"})
        self.assertEqual(reopened.key("ipinfo"), "replacement")
        blank = self.client.put("/api/tools/ipinfo/key", headers=self.headers, json={"key": " "})
        self.assertEqual(blank.status_code, 400)
        self.assertEqual(reopened.key("ipinfo"), "replacement")
        self.client.delete("/api/tools/ipinfo/key", headers=self.headers)
        self.assertEqual(reopened.key("ipinfo"), "")

    def test_csrf_and_origin_and_host(self):
        self.assertEqual(self.client.put("/api/tools/ipinfo/key", json={"key": "x"}).status_code, 403)
        self.assertEqual(self.client.put("/api/tools/ipinfo/key", headers={**self.headers, "origin": "https://evil.example"}, json={"key": "x"}).status_code, 403)
        self.assertEqual(self.client.get("/", headers={"host": "evil.example"}).status_code, 400)

    def test_cache_and_source_provenance(self):
        with patch.object(Providers, "run", return_value=output({"country": "Example"}, {}, [entity("country", "Example", "country")])) as run:
            first = self.wait_job(self.create("ip", "8.8.8.8", ["internetdb"]).json()["id"])
            second = self.wait_job(self.create("ip", "8.8.8.8", ["internetdb"]).json()["id"])
            self.assertEqual(run.call_count, 1)
            self.assertTrue(second["runs"][0]["cached"])
            self.assertEqual(first["runs"][0]["result"]["fetched_at"], second["runs"][0]["result"]["fetched_at"])
            self.assertEqual(second["graph"]["nodes"][1]["sources"][0]["tool"], "internetdb")

    def test_different_credentials_do_not_reuse_cache(self):
        self.store.save_key("ipinfo", "first-key")
        with patch.object(Providers, "run", return_value=output({"country": "Example"})) as run:
            self.wait_job(self.create("ip", "8.8.8.8", ["ipinfo"]).json()["id"])
            self.store.save_key("ipinfo", "second-key")
            job = self.wait_job(self.create("ip", "8.8.8.8", ["ipinfo"]).json()["id"])
            self.assertEqual(run.call_count, 2)
            self.assertFalse(job["runs"][0]["cached"])

    def test_partial_job_keeps_success_and_redacts_exports(self):
        secret = "super-private-key"
        self.store.save_key("ipinfo", secret)
        def run(id, kind, value):
            if id == "internetdb":
                raise ProviderError("timeout", "Source timed out")
            return output({"echo": secret, "api_key": "another-value"})
        with patch.object(Providers, "run", side_effect=run):
            job = self.wait_job(self.create("ip", "8.8.8.8", ["ipinfo", "internetdb"]).json()["id"])
        self.assertEqual(job["status"], "partial")
        self.assertEqual(job["runs"][1]["status"], "timeout")
        export = self.client.get("/api/jobs/" + job["id"] + "/export")
        self.assertNotIn(secret, export.text)
        self.assertNotIn("another-value", export.text)

    def test_disabled_tools_block_on_server(self):
        self.store.enable("phonenumbers", False)
        with patch.object(Providers, "run") as run:
            job = self.wait_job(self.create("phone", "+12025550123", ["phonenumbers"]).json()["id"])
            self.assertEqual(job["runs"][0]["status"], "disabled")
            run.assert_not_called()

    def test_validation(self):
        for kind, value in [("ip", "127.0.0.1"), ("domain", "https://example.org/a"), ("username", "--help"), ("email", "bad@x"), ("evm", "0xwrong"), ("tron", "T" * 34), ("btc", "bad"), ("phone", "2025550123")]:
            with self.subTest(kind=kind):
                self.assertEqual(self.create(kind, value, [next(t.id for t in CATALOG.values() if kind in t.types)]).status_code, 400)
        self.assertEqual(self.create("ip", "8.8.8.8", ["phonenumbers"]).status_code, 400)
        self.assertEqual(validate_target("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

    def test_quota_is_atomic_across_threads(self):
        tool = replace(CATALOG["abuseipdb"], daily=3, interval=0)
        def reserve(_):
            try:
                self.store.reserve(tool)
                return True
            except ProviderError:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(reserve, range(10))), 3)
        self.assertEqual(self.store.quota(tool.id)["used"], 3)

    def test_429_not_found_and_bad_json_distinct(self):
        self.store.save_key("ipinfo", "test")
        for status, content, expected in [(429, {}, "rate_limited"), (404, {}, "not_found"), (401, {}, "auth_error")]:
            with self.subTest(status=status):
                self.store.save_key("ipinfo", "test")
                transport = httpx.MockTransport(lambda req: httpx.Response(status, json=content))
                real_client = httpx.Client(transport=transport)
                with patch("app.providers.httpx.Client", return_value=real_client):
                    with self.assertRaises(ProviderError) as raised:
                        Providers(self.store).ipinfo("ip", "8.8.8.8")
                self.assertEqual(raised.exception.status, expected)

    def test_same_name_candidates_from_different_sources_stay_separate(self):
        engine = self.client.app.state.engine
        job = {"kind": "person", "value": "Alex Smith", "runs": [{"tool": tool, "name": tool, "status": "completed", "result": output({}, entities=[entity("candidate", "Alex Smith", "candidate")])} for tool in ("wikidata", "openalex")]}
        self.assertEqual(len(engine.graph(job)["nodes"]), 3)

    def test_restart_recovers_interrupted_jobs(self):
        self.store.put_job({"id": "old", "created": now(), "kind": "ip", "value": "8.8.8.8", "status": "running", "runs": [{"tool": "ipinfo", "status": "running"}]})
        self.store.recover()
        self.assertEqual(self.store.job("old")["status"], "interrupted")
        self.assertEqual(self.store.job("old")["runs"][0]["status"], "interrupted")


if __name__ == "__main__":
    unittest.main()
