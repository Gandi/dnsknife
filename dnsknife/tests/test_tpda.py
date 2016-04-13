import mock
import os
import unittest

from dnsknife import tpda, Checker, exceptions

here = os.path.dirname(__file__)

class TestTPDA(unittest.TestCase):
    def setUp(self):
        self.client = tpda.Client('domain.com', '{}/test.key'.format(here))

    def fake_txt(self, name):
        return self.client.key_txt()

    def test_url_gen(self):
        with mock.patch('dnsknife.tpda.ServiceLocator.endpoint',
                        returns='http://uri/') as mock_rdap:
            url = self.client.nameservers_uri('tfz.net', ['ns1.','ns2.'])
            mock_rdap.assert_called_with('tfz.net', 'nameservers')
            assert 'signature' in url
            assert 'source' in url
            assert 'expires' in url
            assert 'ns=' in url

        with mock.patch('dnsknife.Checker.txt',
                        side_effect=self.fake_txt) as mock_txt:
            trusted_url = tpda.validate_URI(url)
            assert 'source=domain.com' in trusted_url

    def test_url_bad_signature(self):
        with mock.patch('dnsknife.tpda.ServiceLocator.endpoint',
                        returns='http://uri/') as mock_rdap:
            url = self.client.nameservers_uri('tfz.net', ['ns1.','ns2.'])

        with mock.patch('dnsknife.Checker.txt',
                        side_effect=self.fake_txt) as mock_txt:
            url = url.replace('source=domain', 'source=evil')
            self.assertRaises(exceptions.NoSignatureMatch,
                              tpda.validate_URI, url)
