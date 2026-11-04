import hashlib
import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app.localcsv import CSVSearch, LocalCSV
from app.main import create_app
from app.storage import Store


class CSVTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / '.local' / 'tests'
        root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.tmp.cleanup)
        self.index = LocalCSV(self.tmp.name)
        self.addCleanup(self.index.close)

    def upload(self, text, encoding='utf-8', name='sample.csv', **options):
        raw = text.encode(encoding)
        path = self.index.root / (hashlib.md5(raw).hexdigest() + '.upload')
        path.write_bytes(raw)
        result = self.index.enqueue(path, name, len(raw), hashlib.sha256(raw).hexdigest(), **options)
        for _ in range(300):
            item = next(s for s in self.index.sources() if s['id'] == result['id'])
            if item['status'] != 'importing':
                return item
            time.sleep(.01)
        self.fail('Import did not finish')

    def search(self, value, **kw):
        return self.index.search(CSVSearch(query=value, **kw))

    def test_unicode_phone_format_and_raw_values_and_line_provenance(self):
        source = self.upload('name;phone;email;note\nСемён;+7 (999) 123-45-67;Demo@Example.test;"строка 1\nстрока 2"\n')
        self.assertEqual(source['status'], 'ready')
        self.assertEqual(source['rows'], 1)
        result = self.search('СЕМЕН')['matches'][0]
        self.assertEqual(result['line'], 2)
        self.assertEqual(result['source'], 'sample.csv')
        self.assertEqual(result['data']['note'], 'строка 1\nстрока 2')
        self.assertEqual(self.search('79991234567', mode='exact', field='phone')['returned'], 1)
        self.assertEqual(self.search('demo@example.test', mode='exact')['returned'], 1)
        self.assertEqual(self.search('example.test', mode='exact')['returned'], 0)
        self.assertEqual(self.search('example.test', field='email')['returned'], 1)
        self.assertEqual(self.search('example.test', field='phone')['returned'], 0)

    def test_encodings_delimiters_duplicate_blank_headers_and_leading_zeros(self):
        a = self.upload('Имя;Имя;;id\nАнна;Тест;;000123\n', encoding='cp1251')
        self.assertEqual(a['encoding'], 'cp1251')
        self.assertEqual(a['headers'], ['Имя', 'Имя_2', 'column_3', 'id'])
        self.assertEqual(self.search('000123')['matches'][0]['data']['id'], '000123')
        b = self.upload('name\tcity\nExample\tТестоград\n', encoding='utf-16', name='utf16.csv')
        self.assertEqual(b['delimiter'], '\t')
        self.assertEqual(self.search('тестоград')['returned'], 1)

    def test_paging_filters_archive_restore_and_duplicate(self):
        first = self.upload('email\n' + '\n'.join(f'test{i}@example.test' for i in range(5)))
        second = self.upload('name,email\nOther,test@example.test\n', name='other.csv')
        found = self.search('example.test', sources=[first['id']], limit=2)
        self.assertEqual(found['returned'], 2)
        self.assertTrue(found['has_more'])
        following = self.search('example.test', sources=[first['id']], limit=2, cursor=found['next_cursor'])
        self.assertTrue(set(r['id'] for r in found['matches']).isdisjoint(r['id'] for r in following['matches']))
        self.index.archive(first['id'], True)
        self.assertEqual(self.search('example.test')['returned'], 1)
        self.index.archive(first['id'], False)
        self.assertEqual(self.search('example.test')['returned'], 6)
        self.upload('name,email\nOther,test@example.test\n', name='renamed.csv')
        self.assertEqual(len(self.index.sources()), 2)
        self.assertEqual(self.search('example.test', sources=[second['id']])['returned'], 1)

    def test_failed_import_removes_committed_batches_and_supports_retry(self):
        source = self.upload('name,email\n' + 'Example,test@example.test\n' * 1001 + 'bad,extra,column\n')
        self.assertEqual(source['status'], 'failed')
        self.assertIn('1003', source['message'])
        self.assertEqual(self.search('example')['returned'], 0)
        with self.index.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM records').fetchone()[0], 0)

    def test_fts_punctuation_is_literal_and_empty_search_rejected(self):
        self.upload('email,note\na@example.test,"quote ""word"" 50% _x"\n')
        self.assertEqual(self.search('"word"')['returned'], 1)
        self.assertEqual(self.search('a@example.test')['returned'], 1)
        self.assertEqual(self.search('50%')['returned'], 1)
        self.assertEqual(self.search('OR NOT')['returned'], 0)
        self.assertEqual(self.search('_x')['returned'], 1)
        with self.assertRaises(ValueError):
            self.search('  ')

    def test_corrupt_original_text_warns_and_blank_rows_skipped(self):
        source = self.upload('Им�;name\nvalue;Demo\n\n;\n')
        self.assertEqual(source['rows'], 1)
        self.assertIn('повреждённый', source['message'])

    def test_persistent_index(self):
        self.upload('name\nExample\n')
        self.index.close()
        self.index = LocalCSV(self.tmp.name)
        self.addCleanup(self.index.close)
        self.assertEqual(self.search('example')['returned'], 1)


class CSVAPITests(unittest.TestCase):
    def test_upload_search_and_local_boundary(self):
        root = Path(__file__).resolve().parents[1] / '.local' / 'tests'
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as tmp:
            store = Store(Path(tmp)/'data', Path(tmp)/'secrets')
            with TestClient(create_app(store)) as client:
                headers = {'x-chimera-csrf': client.get('/api/bootstrap').json()['csrf'], 'content-type': 'application/octet-stream'}
                path = '/api/local-csv/sources?name=test.csv'
                self.assertEqual(client.post(path, content=b'name\nExample\n').status_code, 403)
                self.assertEqual(client.post(path, headers=headers, content=b'').status_code, 400)
                result = client.post(path, headers=headers, content=b'name\nExample\n')
                self.assertEqual(result.status_code, 202)
                for _ in range(100):
                    source = client.get('/api/local-csv/sources').json()['sources'][0]
                    if source['status'] != 'importing':
                        break
                    time.sleep(.01)
                json_headers = {'x-chimera-csrf': headers['x-chimera-csrf']}
                result = client.post('/api/local-csv/search', headers=json_headers, json={'query': 'example'})
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json()['returned'], 1)
                self.assertEqual(result.headers['cache-control'], 'no-store')
                self.assertEqual(client.post('/api/local-csv/search', headers=json_headers, json={'query': 'x'}).status_code, 422)
                self.assertEqual(client.post('/api/local-csv/sources?name=bad.txt', headers=headers, content=b'xxx').status_code, 400)
                self.assertFalse(list((store.root/'csv').glob('*.upload')))
