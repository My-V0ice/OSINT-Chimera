import hashlib
import importlib.util
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from app.catalog import CATALOG
from app.main import create_app
from app.presentation import present
from app.providers import Providers, ProviderError, output
from app.storage import Store


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


accounts = load("account_results")
checker = load("accounts_json")


class AccountParsingTests(unittest.TestCase):
    def test_socialscan_string_booleans_and_errors(self):
        data = {"query": [
            {"platform": "positive", "success": "True", "valid": "True", "available": "False"},
            {"platform": "negative", "success": "True", "valid": "True", "available": "True"},
            {"platform": "reserved", "success": "True", "valid": "False", "available": "False"},
            {"platform": "blocked", "success": "False", "valid": "True", "available": "False"},
            {"platform": "incomplete", "success": "True", "valid": "True"}]}
        found, problems, rows = accounts.normalize("socialscan", data)
        self.assertEqual([r["platform"] for r in found], ["positive"])
        self.assertEqual(len(problems), 2)
        self.assertEqual(len(rows), 5)
        self.assertNotIn("status", data["query"][0])

    def test_phone_error_response_is_not_registered(self):
        self.assertIsNone(checker.phone_evidence("instagram", httpx.Response(200, json={"status": "fail", "message": "Please wait"})))
        self.assertIsNone(checker.phone_evidence("instagram", httpx.Response(429, json={"user": {"pk": 1, "username": "a"}})))
        self.assertIs(checker.phone_evidence("instagram", httpx.Response(200, json={"users": [{"pk": 1, "username": "a"}]})), True)
        self.assertIs(checker.phone_evidence("instagram", httpx.Response(200, json={"message": "No users found"})), False)
        self.assertIsNone(checker.phone_evidence("amazon", httpx.Response(200, text='<title>Robot check</title><div id="auth-password-missing-alert">')))
        self.assertIsNone(checker.phone_evidence("snapchat", httpx.Response(200, json={"status_code": "CHALLENGE"})))

    def test_wmn_explicit_detection_and_unknown(self):
        site = {"e_code": 200, "e_string": "profile marker", "m_code": 200, "m_string": "missing marker"}
        self.assertEqual(checker.classify_site(site, 200, "profile marker"), "found")
        self.assertEqual(checker.classify_site(site, 200, "missing marker"), "not_found")
        self.assertEqual(checker.classify_site(site, 200, "login page"), "unknown")
        self.assertEqual(checker.classify_site(site, 403, "profile marker"), "blocked")
        self.assertEqual(checker.classify_site(site, 200, "profile marker missing marker"), "unknown")
        self.assertEqual(checker.classify_site(site, 200, "profile marker Just a moment..."), "blocked")

    def test_wmn_bounded_balanced_selection_skips_unsupported(self):
        def site(n, **kwargs):
            return {"name": str(n), "uri_check": "https://example.org/{account}", "cat": "social", **kwargs}
        data = {"sites": [site(i) for i in range(90)] + [site('post', post_body='{}'), site('protected', protection=['captcha']), site('broken', valid=False), site('music', cat='music')]}
        selected = checker.select_sites(data)
        self.assertEqual(len(selected), 60)
        self.assertIn('music', [s['name'] for s in selected])
        self.assertFalse({'post', 'protected', 'broken'} & {s['name'] for s in selected})

    def test_only_findings_in_center_and_uncertain_not_empty(self):
        for tool in ("socialscan", "ignorant", "whatsmyname"):
            run = {"status": "partial", "result": output({"account_findings": [], "account_checks": [{"status": "unknown"}]})}
            result = present(tool, run)
            self.assertEqual(result['state'], 'partial')
            self.assertFalse(result['empty'])
            self.assertEqual(result['data'], {})
            run['status'] = 'completed'
            run['result']['raw']['account_checks'] = [{'status': 'not_found'}]
            self.assertEqual(present(tool, run)['state'], 'empty')
        empty = present('github', {"status": "completed", "result": output({"total_count": 0, "items": []})})
        self.assertEqual(empty['state'], 'empty')


class AccountApiTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / '.local' / 'tests'
        root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.tmp.cleanup)
        self.store = Store(Path(self.tmp.name) / 'data', Path(self.tmp.name) / 'secrets')
        self.providers = Providers(self.store)

    def test_gravatar_hash_and_related_accounts(self):
        self.store.save_key('gravatar', 'local-test-key')
        raw = {'profile_url': 'https://gravatar.com/example', 'display_name': 'Example', 'verified_accounts': [{'url': 'https://github.com/example', 'service_label': 'GitHub', 'is_verified': True}]}
        with patch.object(self.providers, 'fetch', return_value=raw) as fetch:
            result = self.providers.run('gravatar', 'email', ' Example@EXAMPLE.org ')
        args = fetch.call_args
        self.assertTrue(args.args[1].endswith(hashlib.sha256(b'example@example.org').hexdigest()))
        self.assertNotIn('Example@', args.args[1])
        self.assertEqual(args.kwargs['headers']['Authorization'], 'Bearer local-test-key')
        self.assertEqual(len(result['entities']), 2)

    def test_gravatar_missing_key_does_not_call_network(self):
        with patch.object(self.providers, 'fetch') as fetch, self.assertRaises(ProviderError) as e:
            self.providers.run('gravatar', 'email', 'a@example.org')
        self.assertEqual(e.exception.status, 'requires_key')
        fetch.assert_not_called()

    def test_github_optional_key_and_public_email_search(self):
        raw = {'items': [{'login': 'example', 'html_url': 'https://github.com/example'}], 'total_count': 40, 'incomplete_results': True}
        with patch.object(self.providers, 'fetch', return_value=raw) as fetch:
            result = self.providers.run('github', 'email', 'a@example.org')
        self.assertIn('in:email', fetch.call_args.args[2]['q'])
        self.assertNotIn('Authorization', fetch.call_args.args[3])
        self.assertTrue(result['partial'])
        self.assertFalse(result['entities'][0]['attributes']['confirmed_owner'])
        self.store.save_key('github', 'test-token')
        with patch.object(self.providers, 'fetch', return_value={'login': 'example', 'html_url': 'https://github.com/example'} ) as fetch:
            self.providers.run('github', 'username', 'example')
        self.assertEqual(fetch.call_args.kwargs['headers']['Authorization'], 'Bearer test-token')

    def test_github_403_quota_is_not_auth_failure(self):
        response = httpx.Response(403, headers={'x-ratelimit-remaining': '0', 'x-ratelimit-reset': str(int(time.time()+180))}, json={'message': 'rate limited'})
        with patch('app.providers.httpx.Client') as client:
            client.return_value.__enter__.return_value.stream.return_value.__enter__.return_value = response
            with self.assertRaises(ProviderError) as caught:
                self.providers.fetch('github', 'https://api.github.com/users/example')
        self.assertEqual(caught.exception.status, 'rate_limited')
        self.assertGreater(self.store.quota('github')['blocked_until'], time.time())

    def test_catalog_and_new_runner_history(self):
        with TestClient(create_app(self.store)) as client:
            tools = {t['id']: t for t in client.get('/api/tools').json()}
            self.assertEqual(len(tools), 30)
            self.assertEqual(tools['gravatar']['state'], 'requires_key')
            self.assertEqual(tools['github']['state'], 'ready')
            csrf = client.get('/api/bootstrap').json()['csrf']
            with patch('app.service.Engine.runner_health', return_value={'tools': ['socialscan', 'ignorant', 'whatsmyname']}), patch.object(Providers, 'runner', return_value=output({'account_findings': [{'platform': 'Example', 'status': 'taken'}], 'account_checks': [{'status': 'taken'}]})):
                job = client.post('/api/tools/socialscan/runs', headers={'x-chimera-csrf': csrf}, json={'kind': 'email', 'value': 'a@example.org'}).json()
                for _ in range(100):
                    result = client.get('/api/tools/socialscan/runs/' + job['id']).json()
                    if result['run']['status'] not in {'queued', 'running'}:
                        break
                    time.sleep(.02)
            self.assertEqual(result['presentation']['data'][0]['platform'], 'Example')
            self.assertEqual(client.get('/api/tools/socialscan/runs').json()[0]['id'], job['id'])
