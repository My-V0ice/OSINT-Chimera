import copy
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app.main import create_app
from app.presentation import present
from app.providers import Providers, ProviderError
from app.storage import Store


def response(**flags):
    return {'status': 'ok', '8.8.8.8': {'detections': {'proxy': False, 'vpn': False, 'tor': False, 'hosting': False, 'risk': 0, 'confidence': 0, **flags}, 'network': {'provider': 'Example', 'asn': 'AS15169'}}, 'query_time': 1}


class ProxyCheckTests(unittest.TestCase):
    def setUp(self):
        self.store = Mock()
        self.store.config.return_value = {'enabled': True}
        self.store.key.return_value = ''
        self.provider = Providers(self.store)

    def test_keyless_negative_is_success_false_and_zero_are_visible(self):
        raw = response(anonymous=True)
        before = copy.deepcopy(raw)
        with patch.object(self.provider, 'fetch', return_value=raw) as fetch:
            result = self.provider.run('proxycheck', 'ip', '8.8.8.8')
        self.assertEqual(fetch.call_args.args, ('proxycheck', 'https://proxycheck.io/v3/8.8.8.8', {'ver': '2026-06-24'}))
        self.assertEqual(result['summary']['Proxy'], False)
        self.assertEqual(result['summary']['VPN'], False)
        self.assertEqual(result['summary']['Анонимный выход'], True)
        self.assertEqual(result['summary']['Риск источника, 0–100'], 0)
        p = present('proxycheck', {'status': 'completed', 'result': result})
        self.assertEqual(p['state'], 'success')
        self.assertIs(p['data']['detections']['vpn'], False)
        self.assertNotIn('query_time', p['data'])
        self.assertEqual(raw, before)

    def test_optional_key_and_positive_detections(self):
        self.store.key.return_value = 'test-key'
        with patch.object(self.provider, 'fetch', return_value=response(proxy=True, vpn=True)) as fetch:
            result = self.provider.run('proxycheck', 'ip', '8.8.8.8')
        self.assertEqual(fetch.call_args.args[2]['key'], 'test-key')
        self.assertIs(result['summary']['VPN'], True)
        self.assertIs(result['summary']['Proxy'], True)
        self.assertNotIn('test-key', str(result))

    def test_ipv6_key_normalization(self):
        raw = {'status': 'ok', '2001:4860:4860:0000:0000:0000:0000:8888': {'detections': {'proxy': False, 'vpn': True}}}
        with patch.object(self.provider, 'fetch', return_value=raw) as fetch:
            result = self.provider.proxycheck('ip', '2001:4860:4860::8888')
        self.assertIn('2001%3A4860%3A4860%3A%3A8888', fetch.call_args.args[1])
        self.assertIs(result['summary']['VPN'], True)

    def test_warning_preserves_successful_data(self):
        raw = response(); raw.update(status='warning', message='You are within 10% of your query limit for the day.')
        with patch.object(self.provider, 'fetch', return_value=raw):
            result = self.provider.proxycheck('ip', '8.8.8.8')
        self.assertFalse(result['partial'])
        self.assertIn('10%', result['notes'][-1])
        self.assertEqual(present('proxycheck', {'status': 'completed', 'result': result})['state'], 'success')

    def test_denied_and_error_payloads_not_negative_vpn_results(self):
        for raw, expected in [({'status': 'denied', 'message': 'Free queries exhausted'}, 'rate_limited'), ({'status': 'denied', 'message': 'Invalid API key'}, 'auth_error'), ({'status': 'denied', 'message': 'Access blocked'}, 'blocked'), ({'status': 'error', 'message': 'Failed'}, 'source_error')]:
            with self.subTest(expected=expected), patch.object(self.provider, 'fetch', return_value=raw), self.assertRaises(ProviderError) as error:
                self.provider.proxycheck('ip', '8.8.8.8')
            self.assertEqual(error.exception.status, expected)
        self.store.feedback.assert_called_with('proxycheck', {}, True)

    def test_missing_or_malformed_detections_never_default_to_false(self):
        for raw in [[], {'status': 'ok'}, {'status': 'ok', '1.1.1.1': {'detections': {'proxy': False, 'vpn': False}}}, {'status': 'ok', '8.8.8.8': {'detections': {'proxy': 'no', 'vpn': 'no'}}}, {'status': 'ok', '8.8.8.8': {'detections': {'proxy': False}}}]:
            with self.subTest(raw=raw), patch.object(self.provider, 'fetch', return_value=raw), self.assertRaises(ProviderError) as error:
                self.provider.proxycheck('ip', '8.8.8.8')
            self.assertEqual(error.exception.status, 'source_error')

    def test_api_catalog_run_and_raw_json_without_key(self):
        root = Path(__file__).resolve().parents[1] / '.local' / 'tests'
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as tmp:
            store = Store(Path(tmp)/'data', Path(tmp)/'secrets')
            with TestClient(create_app(store)) as client:
                catalog = client.get('/api/tools').json()
                tool = next(t for t in catalog if t['id'] == 'proxycheck')
                self.assertEqual(len(catalog), 30)
                self.assertEqual(tool['state'], 'ready')
                self.assertTrue(tool['optional_key']); self.assertFalse(tool['has_key'])
                csrf = client.get('/api/bootstrap').json()['csrf']
                raw = response()
                with patch.object(Providers, 'fetch', return_value=raw):
                    job = client.post('/api/tools/proxycheck/runs', headers={'x-chimera-csrf': csrf}, json={'kind': 'ip', 'value': '8.8.8.8'}).json()
                    for _ in range(100):
                        data = client.get('/api/tools/proxycheck/runs/'+job['id']).json()
                        if data['run']['status'] not in {'queued', 'running'}:
                            break
                        time.sleep(.01)
                self.assertEqual(data['run']['status'], 'completed')
                self.assertEqual(data['presentation']['state'], 'success')
                self.assertEqual(data['raw_json'], raw)
                self.assertIs(data['presentation']['summary']['VPN'], False)
