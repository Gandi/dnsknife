from __future__ import absolute_import

import mock
import os
import unittest

from .. import tpda, exceptions


here = os.path.dirname(__file__)


class TestTPDA(unittest.TestCase):
    def setUp(self):
        self.client = tpda.Client('domain.com', '{}/test.key'.format(here))

    def test_url_gen(self):
        with mock.patch('dnsknife.tpda.ServiceLocator.endpoint',
                        return_value='http://uri/') as mock_rdap:
            url = self.client.nameservers_uri('tfz.net', ['ns1.', 'ns2.'])
            mock_rdap.assert_called_with('tfz.net', 'nameservers')
            assert 'signature' in url
            assert 'source' in url
            assert 'expires' in url
            assert 'ns=' in url

        with mock.patch('dnsknife.Checker.txt',
                        return_value=self.client.key_txt()):
            trusted_url = tpda.validate_URI(url)
            assert 'source=domain.com' in trusted_url

    def test_url_bad_signature(self):
        with mock.patch('dnsknife.tpda.ServiceLocator.endpoint',
                        return_value='http://uri/'):
            url = self.client.nameservers_uri('tfz.net', ['ns1.', 'ns2.'])

        with mock.patch('dnsknife.Checker.txt',
                        return_value=self.client.key_txt()):
            url = url.replace('source=domain', 'source=evil')
            self.assertRaises(exceptions.NoSignatureMatch,
                              tpda.validate_URI, url)
