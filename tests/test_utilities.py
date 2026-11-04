import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import create_app
from app.presentation import compact, EMPTY, present
from app.providers import Providers, output, entity, ProviderError
from app.storage import Store


class PresentationTests(unittest.TestCase):
    def test_empty_fields_removed_recursively_but_zero_and_false_retained(self):
        raw = {"nothing": None, "blank": "  ", "empty": [], "nested": {"present": 0, "flag": False, "missing": ""}, "records": [None, {}, {"n": 0}]}
        self.assertEqual(compact(raw), {"nested": {"present": 0, "flag": False}, "records": [{"n": 0}]})
        self.assertIsNone(raw["nothing"])

    def test_missing_results_are_empty_not_errors(self):
        for tool, raw in [("wikidata", {"search": []}), ("openalex", {"results": [], "meta": {"count": 0}}), ("dns", {"status": "NXDOMAIN"}), ("geolite", {"GeoLite2-Country.mmdb": {"not_found": True}}), ("internetdb", {"ip": "8.8.8.8", "ports": [], "vulns": []})]:
            with self.subTest(tool=tool):
                result = present(tool, {"status": "completed", "result": output(raw, {"Пусто": None})})
                self.assertEqual(result["state"], "empty")
                self.assertEqual(result["summary"], {})
        self.assertEqual(present("ipinfo", {"status": "not_found"})["state"], "empty")

    def test_negative_registration_and_missing_profiles_not_findings(self):
        rows = [{"name": "negative", "exists": False}, {"name": "limited", "exists": True, "rateLimit": True}]
        self.assertEqual(present("holehe", {"status": "completed", "result": output({"reports": {"holehe.json": rows}})})["state"], 'partial')
        rows.append({"name": "positive", "exists": True, "emailrecovery": None})
        result = present("holehe", {"status": "completed", "result": output({"reports": {"holehe.json": rows}})})
        self.assertEqual([r["name"] for r in result["data"]], ["positive"])
        for tool in ("maigret", "sherlock"):
            result = present(tool, {"status": "completed", "result": output({"reports": {"data": [{"exists": "False", "url_user": "https://example.org"}]}})})
            self.assertEqual(result["state"], "empty")

    def test_errors_never_become_nothing_found_and_partial_data_survives(self):
        for status in ("network_error", "timeout", "auth_error", "rate_limited", "requires_key"):
            self.assertEqual(present("ipinfo", {"status": status})["state"], "error")
        result = present("dns", {"status": "partial", "result": output({"A": {"values": ["8.8.8.8"]}, "AAAA": {"values": []}}, partial=True)})
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["data"], {"A": {"values": ["8.8.8.8"]}})
        result = present("dns", {"status": "partial", "result": output({"A": {"status": "error"}, "AAAA": {"values": [], "status": "no_answer"}}, partial=True)})
        self.assertEqual(result["state"], "partial")
        self.assertFalse(result["empty"])

    def test_phoneinfoga_queries_remain_separate_and_fields_complete(self):
        raw = {"parsed": {"local": {"country_code": "US", "e164": "+12025550123", "carrier": None}}, "stdout": "original"}
        result = present("phoneinfoga", {"status": "completed", "result": {**output(raw), "searches": [{"label": "example.org", "query": "a query"}]}})
        self.assertEqual(result["data"], {"country_code": "US", "e164": "+12025550123"})
        self.assertEqual(len(result["searches"]), 1)
        self.assertEqual(raw["stdout"], "original")


class UtilityApiTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / ".local" / "tests"
        root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name)/"data", Path(self.tmp.name)/"secrets")
        self.client = TestClient(create_app(self.store))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        self.headers = {"x-chimera-csrf": self.client.get("/api/bootstrap").json()["csrf"]}

    def run_tool(self, tool="phonenumbers", kind="phone", value="+12025550123"):
        r = self.client.post("/api/tools/"+tool+"/runs", headers=self.headers, json={"kind": kind, "value": value})
        self.assertEqual(r.status_code, 202)
        id = r.json()["id"]
        for _ in range(120):
            data = self.client.get(f"/api/tools/{tool}/runs/{id}").json()
            if data["run"]["status"] not in {"queued", "running"}:
                return data
            time.sleep(.02)
        self.fail("Utility did not complete")

    def test_single_utility_standalone_run_has_no_case_or_graph(self):
        result = self.run_tool()
        self.assertEqual(result["run"]["tool"], "phonenumbers")
        self.assertEqual(result["presentation"]["state"], "success")
        self.assertEqual(result["raw_json"]["e164"], "+12025550123")
        self.assertNotIn("graph", result)
        self.assertEqual(self.store.cases(), [])
        self.assertEqual(len(self.client.get('/api/tools/phonenumbers/runs').json()), 1)
        self.assertEqual(self.client.get('/api/tools/dns/runs').json(), [])
        self.assertEqual(self.client.get('/api/tools/dns/runs/'+result['id']).status_code, 404)

    def test_missing_key_server_blocks_and_no_external_call(self):
        with patch.object(Providers, "run") as external:
            result = self.run_tool("ipinfo", "ip", "8.8.8.8")
            external.assert_not_called()
        self.assertEqual(result["run"]["status"], "requires_key")
        self.assertEqual(result["presentation"]["state"], "error")

    def test_raw_keeps_empty_fields_but_center_filters_and_export_redacts(self):
        self.store.save_key("ipinfo", "credential-for-test")
        raw = {"ip": "8.8.8.8", "country": "US", "unused": None, "array": [], "zero": 0, "flag": False, "echo": "credential-for-test"}
        with patch.object(Providers, "run", return_value=output(raw)):
            result = self.run_tool("ipinfo", "ip", "8.8.8.8")
        self.assertIn("unused", result["raw_json"])
        self.assertNotIn("unused", result["presentation"]["data"])
        self.assertEqual(result["presentation"]["data"]["zero"], 0)
        exported = self.client.get(f"/api/tools/ipinfo/runs/{result['id']}/export")
        self.assertNotIn("credential-for-test", exported.text)
        self.assertIsNone(exported.json()["raw_json"]["unused"])

    def test_legacy_multi_tool_history_opens_only_selected_response(self):
        original = {"id": "legacy", "kind": "email", "value": "name@example.org", "created": "2026-10-27", "status": "completed", "runs": [{"tool": tool, "status": "completed", "result": output({"provider": tool})} for tool in ("dns", "holehe")]}
        self.store.put_job(original)
        self.assertEqual(len(self.client.get('/api/tools/dns/runs').json()), 1)
        result = self.client.get('/api/tools/dns/runs/legacy').json()
        self.assertEqual(result["raw_json"], {"provider": "dns"})
        self.assertNotIn('holehe', str(result))
        self.assertEqual(self.store.job("legacy"), original)

    def test_bad_input_does_not_launch_any_tool(self):
        with patch.object(Providers, "run") as external:
            r = self.client.post('/api/tools/phonenumbers/runs', headers=self.headers, json={"kind": "ip", "value": "8.8.8.8"})
            self.assertEqual(r.status_code, 400)
            external.assert_not_called()
        self.assertEqual(self.client.post('/api/tools/missing/runs', headers=self.headers, json={"kind": "phone", "value": "+12025550123"}).status_code, 404)


if __name__ == '__main__':
    unittest.main()
