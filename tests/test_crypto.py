import importlib.util
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.crypto import Options, validate_options, scaled, btc_rows, account_rows, filtered, investigate, tron_address, tron_native
from app.providers import Providers, ProviderError
from app.main import create_app
from app.storage import Store
from app.presentation import present

ADDR = '0x'+'1'*40
OTHER = '0x'+'2'*40
BTC = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT'
TX = 'a'*64


def bitcoin(txid=TX):
    return {'txid': txid, 'vin': [{'prevout': {'scriptpubkey_address': BTC}}, {'prevout': {'scriptpubkey_address': 'other'}}], 'vout': [{'scriptpubkey_address': 'recipient', 'value': 100000001}, {'scriptpubkey_address': BTC, 'value': 7}], 'status': {'confirmed': True, 'block_time': 1700000000}}


class CryptoTests(unittest.TestCase):
    def test_amounts_are_exact_and_unknown_decimals_not_invented(self):
        self.assertEqual(scaled('123456789012345678901234567890', 18), '123456789012.34567890123456789')
        self.assertEqual(scaled('1', 8), '0.00000001')
        self.assertEqual(scaled('0', 18), '0')
        self.assertEqual(scaled('-12', 6), '-0.000012')
        self.assertIsNone(scaled('1', 255))
        rows = account_rows([{'hash': TX, 'from': ADDR, 'to': OTHER, 'value': '1234567', 'tokenDecimal': '6', 'tokenSymbol': 'USDT'}], ADDR, 'ETH', 'ETH', '', 'token')
        self.assertEqual(rows[0]['amount'], '1.234567')

    def test_btc_multi_input_outputs_and_spending_are_not_net_allocations(self):
        rows = btc_rows(bitcoin(), BTC, [{'spent': True, 'txid': 'b'*64}, {'spent': False}])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['from'], [BTC, 'other'])
        self.assertEqual(rows[0]['amount'], '1.00000001')
        self.assertEqual(rows[1]['direction'], 'self')
        self.assertEqual(rows[0]['spending_txid'], 'b'*64)
        self.assertIs(rows[1]['spent'], False)

    def test_btc_coinbase_null_prevout_does_not_fail(self):
        tx=bitcoin();tx['vin']=[{'is_coinbase':True,'prevout':None}];tx['vout']=[{'scriptpubkey_address':BTC,'value':5000000000}]
        r=btc_rows(tx,BTC)
        self.assertEqual(r[0]['amount'],'50');self.assertEqual(r[0]['from'],[])

    def test_filters_use_decimal_and_loaded_pages_only(self):
        rows = account_rows([{'hash': TX, 'from': ADDR, 'to': OTHER, 'value': '1000000000000000001', 'timeStamp': '1700000000'}], ADDR, 'ETH', 'ETH', '')
        self.assertEqual(len(filtered(rows, Options(direction='out', minimum='1.000000000000000001'))), 1)
        self.assertEqual(filtered(rows, Options(maximum='1')), [])
        self.assertEqual(filtered(rows, Options(direction='in')), [])
        self.assertEqual(filtered(rows, Options(since='2025-01-01T00:00:00Z')), [])
        huge={**rows[0],'amount':'123456789012345678901234567890.000000000000000001'}
        self.assertEqual(filtered([huge],Options(minimum='123456789012345678901234567890.000000000000000002')),[])

    def test_query_limits_and_cursor_do_not_accept_urls(self):
        for options in ({'pages': 4}, {'spend_checks': 6}, {'minimum': '-1'}, {'since': 'invalid'}, {'unknown': True}):
            with self.assertRaises(ValueError): validate_options(['esplora'], 'btc', options)
        with self.assertRaises(ValueError):validate_options(['ethereumetl'], 'evm', {'start_block': 1, 'end_block': 21})
        p = Mock()
        with self.assertRaises(ValueError):investigate(p, 'esplora', 'btc', BTC, {'cursor': 'https://example.org', 'spend_checks': 0})
        p.fetch.assert_not_called()

    def test_esplora_pages_and_outspends_are_bounded(self):
        p = Mock()
        page = [bitcoin(f'{n:064x}') for n in range(25)]
        p.fetch.side_effect = [page, [{'spent': False}, {'spent': False}], page]
        result = investigate(p, 'esplora', 'btc', BTC, {'pages': 2, 'spend_checks': 1})
        self.assertEqual(p.fetch.call_count, 3)
        self.assertEqual(result['crypto']['loaded'], 50)
        self.assertEqual(result['crypto']['next_cursor'], page[-1]['txid'])
        self.assertIn('/txs/chain/'+page[-1]['txid'], p.fetch.call_args_list[-1].args[1])

    def test_focus_spending_transaction_uses_fixed_tx_path(self):
        p = Mock();p.fetch.return_value = bitcoin()
        r = investigate(p, 'esplora', 'btc', BTC, {'focus_txid': TX, 'spend_checks': 0})
        self.assertIn('/tx/'+TX, p.fetch.call_args.args[1]); self.assertEqual(r['crypto']['next_cursor'], '')

    def test_blockscout_key_chain_and_empty_success(self):
        p=Mock();p.store.key.return_value='secret';p.fetch.return_value={'status':'0','message':'No transactions found','result':[]}
        r=investigate(p,'blockscout','evm',ADDR,{'chain':'8453'})
        params=p.fetch.call_args.args[2]
        self.assertEqual(params['chain_id'],'8453');self.assertEqual(params['apikey'],'secret')
        self.assertEqual(present('blockscout',{'status':'completed','result':r})['state'],'empty')
        self.assertNotIn('secret',json.dumps(r))

    def test_blockscout_failure_not_empty_and_later_failure_partial(self):
        p=Mock();p.fetch.return_value={'status':'0','message':'NOTOK','result':'Invalid API Key'}
        with self.assertRaises(ProviderError) as error:investigate(p,'blockscout','evm',ADDR,{})
        self.assertEqual(error.exception.status,'auth_error')
        p.fetch.side_effect=[{'status':'1','result':[{'hash':f'{i:064x}','from':ADDR,'to':OTHER,'value':'1'} for i in range(50)]},ProviderError('rate_limited','limit')]
        r=investigate(p,'blockscout','evm',ADDR,{'pages':2})
        self.assertTrue(r['partial']);self.assertEqual(len(r['crypto']['rows']),50)

    def test_trongrid_only_uses_fingerprint_not_next_url(self):
        p=Mock();p.store.key.return_value='secret'
        page={'success':True,'data':[],'meta':{'fingerprint':'cursor1','links':{'next':'https://untrusted.invalid/'}}}
        p.fetch.side_effect=[page,{'success':True,'data':[],'meta':{}}]
        investigate(p,'trongrid','tron','TAddress',{'pages':2})
        self.assertTrue(p.fetch.call_args.args[1].startswith('https://api.trongrid.io/'))
        self.assertEqual(p.fetch.call_args.args[2]['fingerprint'],'cursor1')

    def test_trx_native_hex_addresses_and_amount_are_decoded(self):
        from app.providers import base58check
        address='TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7'
        hex_address=base58check(address).hex()
        self.assertEqual(tron_address(hex_address),address)
        rows=tron_native([{'txID':TX,'raw_data':{'contract':[{'type':'TransferContract','parameter':{'value':{'owner_address':hex_address,'to_address':hex_address,'amount':1000001}}}]},'ret':[{'contractRet':'SUCCESS'}]}])
        normalized=account_rows(rows,address,'TRON','TRX','','native',tron=True)
        self.assertEqual(normalized[0]['amount'],'1.000001');self.assertEqual(normalized[0]['to'],[address])

    def test_graphsense_net_change_does_not_invent_counterparties(self):
        p=Mock();p.store.endpoint.return_value='http://graphsense:9000';p.store.key.return_value=''
        p.fetch.return_value={'address_txs':[{'tx_hash':TX,'tx_type':'utxo','currency':'btc','timestamp':1700000000,'value':{'value':-42}}],'next_page':None}
        result=investigate(p,'graphsense','btc',BTC,{})
        r=result['crypto']['rows'][0]
        self.assertEqual(r['direction'],'out');self.assertEqual(r['amount'],'-0.00000042')
        self.assertEqual(r['from'],[]);self.assertEqual(r['to'],[])

    def test_graphsense_empty_record_is_partial_not_a_finding(self):
        p=Mock();p.store.endpoint.return_value='http://graphsense:9000';p.store.key.return_value=''
        p.fetch.return_value={'address_txs':[{}],'next_page':None}
        result=investigate(p,'graphsense','btc',BTC,{})
        self.assertTrue(result['partial']);self.assertEqual(result['crypto']['rows'],[])


class CryptoApiTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[1]/'.local'/'tests';root.mkdir(parents=True,exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=root);self.addCleanup(self.tmp.cleanup)
        self.store=Store(Path(self.tmp.name)/'data',Path(self.tmp.name)/'secrets')
        self.client=TestClient(create_app(self.store));self.client.__enter__();self.addCleanup(self.client.__exit__,None,None,None)
        self.headers={'x-chimera-csrf':self.client.get('/api/bootstrap').json()['csrf']}

    def test_connection_encrypted_hidden_and_configuration_prerequisites(self):
        secret='https://rpc.example.org/private-credential'
        initial={t['id']:t for t in self.client.get('/api/tools').json()}
        self.assertEqual(len(initial),30);self.assertEqual(initial['graphsense']['state'],'requires_configuration')
        for url in ('file:///tmp/key','http://user:pass@example.org','javascript:alert(1)'):
            self.assertEqual(self.client.put('/api/tools/graphsense/connection',headers=self.headers,json={'endpoint':url}).status_code,400)
        result=self.client.put('/api/tools/graphsense/connection',headers=self.headers,json={'endpoint':secret})
        self.assertEqual(result.status_code,200);self.assertNotIn(secret,result.text)
        self.assertNotIn(secret.encode(),self.store.path.read_bytes())
        self.assertEqual(self.store.endpoint('graphsense'),secret)
        self.assertNotIn(secret,str(self.store.redact({'url':secret})))
        self.client.put('/api/tools/graphsense/connection',headers=self.headers,json={'endpoint':''})
        self.assertEqual(self.store.endpoint('graphsense'),'')

    def test_invalid_options_rejected_before_job_and_crypto_api_payload(self):
        before=len(self.store.jobs())
        result=self.client.post('/api/tools/esplora/runs',headers=self.headers,json={'kind':'btc','value':BTC,'options':{'pages':100}})
        self.assertEqual(result.status_code,400);self.assertEqual(len(self.store.jobs()),before)
        with patch.object(Providers,'fetch',return_value=[bitcoin()]):
            result=self.client.post('/api/tools/esplora/runs',headers=self.headers,json={'kind':'btc','value':BTC,'options':{'spend_checks':0}}).json()
            for _ in range(100):
                data=self.client.get('/api/tools/esplora/runs/'+result['id']).json()
                if data['run']['status'] not in {'queued','running'}:break
                time.sleep(.01)
        self.assertEqual(data['presentation']['state'],'success')
        self.assertEqual(len(data['presentation']['crypto']['rows']),2)
        self.assertTrue(data['raw_json']['pages']);self.assertEqual(data['options']['spend_checks'],0)
        self.assertEqual(data['options']['asset_filter'],'')
        self.assertEqual(data['presentation']['crypto']['options']['asset_filter'],'')

    def test_public_asset_filter_not_redacted_as_an_authentication_token(self):
        saved={'options':Options(asset_filter='USDT').model_dump()}
        self.store.put_job({'id':'filter-regression','created':'now','kind':'evm','value':ADDR,'status':'completed','runs':[],**saved})
        self.assertEqual(self.store.job('filter-regression')['options']['asset_filter'],'USDT')

    def test_options_are_part_of_cache_identity(self):
        self.store.save_key('blockscout','test-key')
        with patch.object(Providers,'fetch',return_value={'status':'1','result':[]}) as fetch:
            for chain in ['1','10']:
                job=self.client.post('/api/tools/blockscout/runs',headers=self.headers,json={'kind':'evm','value':ADDR,'options':{'chain':chain}}).json()
                for _ in range(100):
                    data=self.client.get('/api/tools/blockscout/runs/'+job['id']).json()
                    if data['run']['status'] not in {'queued','running'}:break
                    time.sleep(.01)
            self.assertEqual(fetch.call_count,2)


class EtlRunnerTests(unittest.TestCase):
    def test_fixed_commands_ranges_and_no_broadcast(self):
        spec=importlib.util.spec_from_file_location('etl_runner',Path(__file__).resolve().parents[1]/'tools'/'etl_runner.py')
        etl=importlib.util.module_from_spec(spec);spec.loader.exec_module(etl)
        task=etl.Task(rpc='https://rpc.example.org',chain='1',event='native',start=1,end=20,address=ADDR)
        cmd=etl.command(task,Path('data.csv'))
        self.assertEqual(cmd[1],'export_blocks_and_transactions');self.assertNotIn('broadcast',cmd)
        self.assertIn('--transactions-output',cmd)
        with self.assertRaises(ValidationError):etl.Task(rpc=task.rpc,chain='1',event='native',start=0,end=20,address=ADDR)
