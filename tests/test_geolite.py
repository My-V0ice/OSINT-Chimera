import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import geoip2.errors
import geoip2.models

from app.presentation import present
from app.providers import Providers, ProviderError


class GeoLiteTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1] / '.local' / 'tests'
        root.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=root)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = patch.dict('os.environ', {'CHIMERA_GEOLITE': str(self.root)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_geoip2_v5_models_serialize_all_three_databases(self):
        # Real v5 models expose to_dict(), not the removed raw attribute.
        city = geoip2.models.City(['en'], country={'iso_code': 'US', 'names': {'en': 'United States'}}, city={'names': {'en': 'Example City'}}, location={'latitude': 0, 'longitude': 0}, ip_address='8.8.8.8', prefix_len=24)
        country = geoip2.models.Country(['en'], country={'iso_code': 'US', 'names': {'en': 'United States'}}, ip_address='8.8.8.8', prefix_len=24)
        asn = geoip2.models.ASN('8.8.8.8', autonomous_system_number=15169, autonomous_system_organization='Google LLC', prefix_len=24)
        for name in ('City', 'Country', 'ASN'):
            (self.root / f'GeoLite2-{name}.mmdb').touch()
        with patch('geoip2.database.Reader') as reader:
            model = reader.return_value.__enter__.return_value
            model.city.return_value, model.country.return_value, model.asn.return_value = city, country, asn
            result = Providers(None).geolite('ip', '8.8.8.8')
        self.assertEqual(len(result['raw']), 3)
        self.assertEqual(result['summary']['Город (приблизительно)'], 'Example City')
        self.assertEqual(result['summary']['ASN'], 15169)
        self.assertEqual(result['raw']['GeoLite2-City.mmdb']['location']['latitude'], 0)
        self.assertEqual(result['raw']['GeoLite2-ASN.mmdb']['network'], '8.8.8.0/24')
        self.assertIn('Google LLC', json.dumps(result))
        self.assertEqual(present('geolite', {'status': 'completed', 'result': result})['state'], 'success')

    def test_missing_ip_is_empty_without_processing_error(self):
        (self.root / 'GeoLite2-Country.mmdb').touch()
        with patch('geoip2.database.Reader') as reader:
            reader.return_value.__enter__.return_value.country.side_effect = geoip2.errors.AddressNotFoundError('Not found')
            result = Providers(None).geolite('ip', '8.8.8.8')
        self.assertEqual(result['raw'], {'GeoLite2-Country.mmdb': {'not_found': True}})
        self.assertEqual(present('geolite', {'status': 'completed', 'result': result})['state'], 'empty')

    def test_missing_database_keeps_configuration_error(self):
        with self.assertRaises(ProviderError) as error:
            Providers(None).geolite('ip', '8.8.8.8')
        self.assertEqual(error.exception.status, 'requires_database')
