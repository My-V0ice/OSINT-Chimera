import copy
import json
import unittest
from unittest.mock import Mock, patch

from app.presentation import present
from app.providers import Providers, ProviderError, output
from app.result_rules import profile_records, profiles_to_entities, harvester_records, spiderfoot_records


class OutputReviewTests(unittest.TestCase):
    def test_actual_empty_harvester_summary_and_command_not_findings(self):
        raw = {'stdout': 'Found 0 hosts', 'tool_version': 'test', 'exit_code': 0, 'reports': {'harvest.jsonl': [{'type': 'summary', 'target': 'example.org', 'cmd': 'theHarvester', 'result_count': 0, 'counts': {}, 'artifacts': [], 'evidence_status': 'complete'}], 'harvest.json': {'cmd': 'test', 'hosts': [], 'shodan': []}}}
        before = copy.deepcopy(raw)
        result = present('theharvester', {'status': 'completed', 'result': output(raw, {'Отчётов': 2})})
        self.assertEqual(result['state'], 'empty')
        self.assertEqual(result['data'], {})
        self.assertEqual(result['summary'], {})
        self.assertEqual(result['diagnostics']['stdout'], 'Found 0 hosts')
        self.assertEqual(raw, before)

    def test_harvester_artifacts_and_legacy_hosts_supported(self):
        raw = {'new.jsonl': [{'type': 'summary', 'artifacts': [{'type': 'email', 'value': 'a@example.org'}]}], 'old.json': {'hosts': ['sub.example.org:8.8.8.8'], 'cmd': 'ignored'}}
        rows = harvester_records(raw)
        self.assertEqual({(r['type'], r['value']) for r in rows}, {('email', 'a@example.org'), ('domain', 'sub.example.org'), ('ip', '8.8.8.8')})

    def test_maigret_nested_status_counts_once_and_negative_parent_stops_recursion(self):
        good = {'url_user': 'https://example.org/a', 'url_main': 'https://example.org', 'status': {'status': 'Claimed', 'url': 'https://example.org/a'}, 'site': {'config': 1}}
        bad = {'url_user': 'https://example.org/b', 'status': {'status': 'Unclaimed', 'nested': {'status': 'Claimed', 'url': 'https://example.org/fake'}}}
        rows = profile_records({'report.json': {'a': good, 'b': bad}})
        self.assertEqual(len(rows), 1)
        self.assertNotIn('site', rows[0])
        self.assertEqual(len(profiles_to_entities(rows)), 1)

    def test_sherlock_header_negative_and_unknown_not_profiles(self):
        rows = [{'exists': x, 'url_user': 'https://example.org/' + str(i)} for i, x in enumerate(['exists', 'False', 'UNKNOWN', 'True'])]
        self.assertEqual(len(profile_records(rows)), 1)

    def test_spiderfoot_seed_is_not_a_finding_but_whois_is(self):
        seed = {'module': 'SpiderFoot UI', 'type': 'Internet Name', 'data': 'example.org'}
        whois = {'module': 'sfp_whois', 'type': 'Domain Whois', 'data': 'Example registry data'}
        self.assertEqual(spiderfoot_records({'events': [seed]}), [])
        result = present('spiderfoot', {'status': 'completed', 'result': output({'reports': {'events': [seed]}}, entities=[{'type': 'domain', 'value': 'example.org'}])})
        self.assertEqual(result['state'], 'empty')
        self.assertEqual(spiderfoot_records({'events': [seed, whois]}), [whois])

    def test_parser_failure_and_rate_limit_do_not_become_empty(self):
        for tool, reports in [('theharvester', {'report.json': {'parse_error': True}}), ('maigret', {'report.json': {'a': {'status': {'status': 'Unknown'}, 'url_user': 'https://example.org/a'}}}), ('holehe', {'holehe.json': [{'name': 'limited', 'exists': True, 'rateLimit': True}]})]:
            result = present(tool, {'status': 'completed', 'result': output({'reports': reports})})
            self.assertEqual(result['state'], 'partial', tool)
            self.assertFalse(result['empty'])
            self.assertFalse(result['data'])
            self.assertFalse(result['items'])

    def test_zero_and_false_are_substantive_checks(self):
        for tool, raw in [('abuseipdb', {'data': {'totalReports': 0, 'isTor': False}}), ('emailrep', {'details': {'blacklisted': False}, 'references': 0})]:
            p = present(tool, {'status': 'completed', 'result': output(raw)})
            self.assertEqual(p['state'], 'success')
            self.assertEqual(p['data'], raw)

    def test_keybase_null_results_not_found_and_failed_payload_rejected(self):
        provider = Providers(Mock())
        raw = {'status': {'code': 0}, 'them': [None]}
        with patch.object(provider, 'fetch', return_value=raw):
            result = provider.keybase('username', 'missing')
        self.assertEqual(present('keybase', {'status': 'completed', 'result': result})['state'], 'empty')
        with patch.object(provider, 'fetch', return_value={'status': {'code': 1}, 'them': []}), self.assertRaises(ProviderError):
            provider.keybase('username', 'missing')

    def test_keybase_related_proofs_and_domain_lookup(self):
        raw = {'status': {'code': 0}, 'them': [{'basics': {'username': 'example'}, 'proofs_summary': {'all': [{'service_url': 'https://github.com/example', 'proof_type': 'github'}]}}]}
        p = Providers(Mock())
        with patch.object(p, 'fetch', return_value=raw) as fetch:
            result = p.keybase('domain', 'example.org')
        self.assertEqual(fetch.call_args.args[2]['domain'], 'example.org')
        self.assertEqual(len(result['entities']), 2)
        self.assertFalse(result['entities'][1]['attributes']['independently_verified'])

    def test_emailrep_requires_key_and_never_reports_an_account_url(self):
        store = Mock(); store.config.return_value = {'enabled': True}; store.key.return_value = ''
        p = Providers(store)
        with patch.object(p, 'fetch') as fetch, self.assertRaises(ProviderError) as error:
            p.run('emailrep', 'email', 'a@example.org')
        self.assertEqual(error.exception.status, 'requires_key'); fetch.assert_not_called()
        store.key.return_value = 'test-key'
        raw = {'email': 'a@example.org', 'reputation': 'none', 'references': 0, 'suspicious': False, 'details': {'profiles': ['example']}}
        with patch.object(p, 'fetch', return_value=raw) as fetch:
            result = p.run('emailrep', 'email', 'a@example.org')
        self.assertEqual(fetch.call_args.kwargs['headers']['Key'], 'test-key')
        self.assertEqual(result['entities'][0]['type'], 'service')
        self.assertEqual(result['entities'][0]['source_url'], '')
        self.assertNotIn('test-key', json.dumps(result))

    def test_pywhat_empty_report_and_type_matches(self):
        for matches, state in [({}, 'empty'), ({'text': [{'Regex': {'Name': 'Email'}, 'Matched': 'a@example.org'}]}, 'success')]:
            result = present('pywhat', {'status': 'completed', 'result': output({'reports': {'pywhat.json': {'Regexes': matches, 'File Signatures': {}}}})})
            self.assertEqual(result['state'], state)

    def test_pywhat_pattern_examples_not_presented_as_observations(self):
        raw = {'reports': {'pywhat.json': {'Regexes': {'text': [{'Matched': 'a@example.org', 'Regex Pattern': {'Name': 'Email', 'Examples': {'Valid': ['unrelated@example.org']}, 'Regex': 'pattern'}}]}}}}
        p = present('pywhat', {'status': 'completed', 'result': output(raw)})
        self.assertEqual(p['data'], [{'matched': 'a@example.org', 'possible_type': 'Email'}])
        self.assertNotIn('unrelated@example.org', json.dumps(p))
        self.assertIn('unrelated@example.org', json.dumps(raw))
