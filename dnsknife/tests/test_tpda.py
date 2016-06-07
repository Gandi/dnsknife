from __future__ import absolute_import

import mock
import os
import unittest

from .. import tpda, exceptions


here = os.path.dirname(__file__)


class TestTPDA(unittest.TestCase):
    def setUp(self):
        self.client = tpda.Client('domain.com', '{}/test.key'.format(here))

    def _test_url_gen(self, fn, service, *args):
        with mock.patch('dnsknife.tpda.ServiceLocator.endpoint',
                        return_value='http://uri/') as mock_rdap:
            url = fn('tfz.net', *args)
            mock_rdap.assert_called_with('tfz.net', service)
            assert 'signature' in url
            assert 'source' in url
            assert 'expires' in url

        with mock.patch('dnsknife.Checker.txt',
                         return_value=self.client.key_txt()), \
              mock.patch('dnsknife.resolver.ns_for',
                         return_value=['1.2.3.4']):
            trusted_url = tpda.validate_URI(url)
            assert 'source=domain.com' in trusted_url

        return url

    def test_nameserver_uri(self):
        uri = self._test_url_gen(self.client.nameservers_uri,
                                 'nameservers', ['ns1.', 'ns2.'])
        assert 'ns=ns1' in uri

    def test_dnssec_uri(self):
        uri = self._test_url_gen(self.client.dnssec_uri, 'dnssec',
                                 13, 'pouetpouet=', 257)
        assert 'flags=257' in uri
        assert 'pubkey=pou' in uri
        assert 'algorithm=13' in uri

    def test_website_uri(self):
        uri = self._test_url_gen(self.client.website_uri, 'website',
                                 ['1.2.3.4', '4.5.6.7'], None, 'alias.')
        assert 'cname=alias' in uri
        assert 'ipv4=' in uri

    def test_email_uri(self):
        uri = self._test_url_gen(self.client.email_uri, 'email',
                                 ['10 mx1.', '20 mx2.'])

        assert 'mx=10+mx1' in uri

    def test_url_bad_signature(self):
        with mock.patch('dnsknife.tpda.ServiceLocator.endpoint',
                        return_value='http://uri/'):
            url = self.client.nameservers_uri('tfz.net', ['ns1.', 'ns2.'])

        with mock.patch('dnsknife.Checker.txt',
                         return_value=self.client.key_txt()), \
              mock.patch('dnsknife.resolver.ns_for',
                         return_value=['1.2.3.4']):
            url = url.replace('source=domain', 'source=evil')
            self.assertRaises(exceptions.NoSignatureMatch,
                              tpda.validate_URI, url)

    def test_url_gen_override(self):
        client = tpda.Client('domain.com', '{}/test.key'.format(here),
                             override_uri='http://localhost:1234')
        url = client.nameservers_uri('tfz.net', ['ns1.', 'ns2.'])

        assert 'signature' in url
        assert 'source' in url
        assert 'expires' in url
        assert 'ns=' in url
        assert url.startswith('http://localhost:1234')
