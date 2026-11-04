import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import create_app
from app.providers import Providers, output, entity
from app.storage import Store, now


class CaseTests(unittest.TestCase):
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

    def create_case(self, title="Объект проверки"):
        r = self.client.post("/api/cases", headers=self.headers, json={"title": title})
        self.assertEqual(r.status_code, 201)
        return r.json()["id"]

    def search(self, id, kind="phone", value="+12025550123", tool="phonenumbers"):
        r = self.client.post("/api/jobs", headers=self.headers, json={"case_id": id, "kind": kind, "value": value, "tools": [tool]})
        self.assertEqual(r.status_code, 202)
        for _ in range(100):
            j = self.client.get("/api/jobs/" + r.json()["id"]).json()
            if j["status"] not in {"queued", "running"}:
                return j
            time.sleep(.02)
        self.fail("Search did not finish")

    def case(self, id):
        r = self.client.get("/api/cases/" + id)
        self.assertEqual(r.status_code, 200)
        return r.json()

    def test_empty_case_rename_and_validation(self):
        id = self.create_case()
        self.assertEqual(self.case(id)["status"], "draft")
        r = self.client.put("/api/cases/" + id, headers=self.headers, json={"title": "Новое имя"})
        self.assertEqual(r.json()["title"], "Новое имя")
        self.assertEqual(self.client.put("/api/cases/" + id, headers=self.headers, json={"title": "  "}).status_code, 400)
        self.assertEqual(self.client.get("/api/cases/missing").status_code, 404)
        self.assertEqual(self.client.post("/api/cases", json={"title": "No CSRF"}).status_code, 403)

    def test_multiple_input_types_shared_facts_and_provenance(self):
        id = self.create_case()
        with patch.object(Providers, "run", return_value=output({"source": "fixture"}, entities=[entity("country", "US", "страна")])):
            phone = self.search(id)
            email = self.search(id, "email", "name@example.org", "dns")
        case = self.case(id)
        self.assertEqual(len(case["searches"]), 2)
        countries = [n for n in case["graph"]["nodes"] if n["type"] == "country"]
        self.assertEqual(len(countries), 1)
        self.assertEqual({s["job_id"] for s in countries[0]["sources"]}, {phone["id"], email["id"]})
        self.assertEqual(len([e for e in case["graph"]["edges"] if e["target"] == countries[0]["id"]]), 2)
        memberships = [e for e in case["graph"]["edges"] if e["source"] == "target"]
        self.assertEqual(len(memberships), 2)
        self.assertTrue(all(e["evidence"][0]["association"] == "hypothesis" for e in memberships))
        self.assertEqual(case["status"], "completed")

    def test_repeated_input_and_same_tool_keep_distinct_searches(self):
        id = self.create_case()
        self.search(id)
        self.search(id)
        case = self.case(id)
        phones = [n for n in case["graph"]["nodes"] if n["type"] == "phone"]
        self.assertEqual(len(phones), 1)
        self.assertEqual(len(phones[0]["input_jobs"]), 2)
        self.assertEqual(len({r["run_id"] for r in case["runs"]}), 2)
        exported = self.client.get("/api/cases/" + id + "/export")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(len(exported.json()["searches"]), 2)
        self.assertTrue(all(s["runs"][0]["result"]["raw"]["e164"] == "+12025550123" for s in exported.json()["searches"]))

    def test_attach_deduplicate_detach_and_case_scoped_confirmation(self):
        first, second = self.create_case("Первый"), self.create_case("Второй")
        original = self.search(first)
        path = "/api/cases/" + second + "/searches"
        with patch.object(Providers, "run") as run:
            for _ in range(2):
                self.assertEqual(self.client.post(path, headers=self.headers, json={"job_id": original["id"]}).status_code, 200)
            run.assert_not_called()
        self.assertEqual(len(self.case(second)["searches"]), 1)
        self.client.put(path + "/" + original["id"], headers=self.headers, json={"association": "confirmed", "note": "Подтверждено вручную"})
        self.assertEqual(self.case(second)["searches"][0]["association"], "confirmed")
        self.assertEqual(self.case(first)["searches"][0]["association"], "hypothesis")
        self.client.delete(path + "/" + original["id"], headers=self.headers)
        self.assertEqual(self.case(second)["searches"], [])
        self.assertEqual(self.client.get("/api/jobs/" + original["id"]).status_code, 200)
        self.store.migrate_cases()
        self.assertEqual(len(self.store.cases()), 2)

    def test_unknown_case_does_not_start_or_save_search(self):
        with patch.object(Providers, "run") as run:
            r = self.client.post("/api/jobs", headers=self.headers, json={"case_id": "missing", "kind": "phone", "value": "+12025550123", "tools": ["phonenumbers"]})
            self.assertEqual(r.status_code, 400)
            self.assertEqual(self.store.jobs(), [])
            run.assert_not_called()

    def test_legacy_migration_preserves_original_responses(self):
        # A fresh database simulates an installation before the cases migration.
        root = Path(self.tmp.name)/"legacy"
        store = Store(root/"data", root/"keys")
        original = {"id": "legacy", "created": now(), "kind": "username", "value": "example", "status": "completed", "runs": []}
        store.put_job(original)
        store.migrate_cases()
        store.migrate_cases()
        self.assertEqual(len(store.cases()), 1)
        self.assertEqual(store.job("legacy"), original)
        self.assertEqual(store.case_searches(store.cases()[0]["id"])[0]["id"], "legacy")

    def test_same_name_candidates_from_different_sources_not_collapsed_in_case(self):
        id = self.create_case()
        with patch.object(Providers, "run", return_value=output({}, entities=[entity("candidate", "Alex Smith", "кандидат")])):
            self.search(id, "person", "Alex Smith", "wikidata")
            self.search(id, "person", "Alex Smith", "openalex")
        candidates = [n for n in self.case(id)["graph"]["nodes"] if n["type"] == "candidate"]
        self.assertEqual(len(candidates), 2)


if __name__ == "__main__":
    unittest.main()
