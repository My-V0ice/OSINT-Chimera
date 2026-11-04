import unittest
import tempfile
from pathlib import Path
from urllib.parse import urlencode

from app.phoneinfoga import normalize, parse_console
from app.storage import Store


URL = "https://www.google.com/search?" + urlencode({"q": 'site:facebook.com intext:"12025550123"'})
LOG = f"""Running scan for phone number +12025550123...

Results for googlesearch
Social media:
    URL: {URL}
    URL: {URL}
General:
    URL: https://www.google.com/search?q=ext%3Apdf+12025550123

Results for local
Raw local: 2025550123
Local: (202) 555-0123
E164: +12025550123
International: 12025550123
Country: US

2 scanner(s) succeeded
"""


class PhoneInfogaTests(unittest.TestCase):
    def test_console_fields_and_search_categories(self):
        parsed = parse_console(LOG)
        self.assertEqual(parsed["local"]["e164"], "+12025550123")
        self.assertEqual(parsed["local"]["country_code"], "US")
        self.assertEqual(len(parsed["searches"]), 2)
        self.assertEqual(parsed["searches"][0]["label"], "facebook.com")
        self.assertEqual(parsed["searches"][0]["category"], "Социальные сети")
        self.assertEqual(parsed["searches"][1]["label"], "Документы")
        self.assertEqual(parsed["searches"][0]["query"], 'site:facebook.com intext:"12025550123"')
        self.assertFalse(parsed["account_search_performed"])

    def test_dorks_never_become_graph_findings_and_original_is_preserved(self):
        result = normalize({"raw": {"stdout": LOG, "stderr": "", "tool_version": "2.11.0"}, "entities": [{"type": "search_url", "value": URL}], "fetched_at": "original-time", "partial": False})
        self.assertEqual([e["type"] for e in result["entities"]], ["country"])
        self.assertEqual(result["entities"][0]["value"], "US")
        self.assertEqual(result["raw"]["stdout"], LOG)
        self.assertEqual(result["fetched_at"], "original-time")
        self.assertEqual(result["summary"]["Подготовлено поисковых запросов"], 2)
        self.assertNotIn("Найдено связей", result["summary"])
        self.assertFalse(result["partial"])

    def test_unknown_output_is_partial_not_empty_success(self):
        result = normalize({"raw": {"stdout": "unsupported output"}, "partial": False})
        self.assertTrue(result["partial"])
        self.assertEqual(result["entities"], [])
        self.assertNotIn("Страна нумерации", result["summary"])

    def test_ansi_section_order_and_untrusted_urls(self):
        log = "\x1b[32mResults for local\x1b[0m\nCountry: US\nResults for googlesearch\nSocial media:\nURL: javascript:alert(1)\nURL: https://evil.example/search?q=anything\nURL: " + URL
        parsed = parse_console(log)
        self.assertEqual(parsed["local"]["country_code"], "US")
        self.assertEqual(len(parsed["searches"]), 1)

    def test_existing_job_reprocessed_once_without_new_lookup(self):
        root = Path(__file__).resolve().parents[1] / ".local" / "tests"
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as folder:
            store = Store(Path(folder)/"data", Path(folder)/"secrets")
            original = {"id": "saved", "kind": "phone", "value": "+12025550123", "created": "original", "status": "completed", "runs": [{"tool": "phoneinfoga", "status": "completed", "adapter_version": "1.0", "result": {"raw": {"stdout": LOG}, "fetched_at": "old-acquisition", "entities": [{"type": "search_url", "value": URL}]}}]}
            store.put_job(original)
            self.assertEqual(store.migrate_phoneinfoga(), 1)
            self.assertEqual(store.migrate_phoneinfoga(), 0)
            updated = store.job("saved")
            run = updated["runs"][0]
            self.assertEqual(run["adapter_version"], "1.1")
            self.assertEqual(run["result"]["fetched_at"], "old-acquisition")
            self.assertEqual(run["result"]["raw"]["stdout"], LOG)
            self.assertEqual(len(run["result"]["entities"]), 1)


if __name__ == "__main__":
    unittest.main()
