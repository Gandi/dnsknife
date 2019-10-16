from __future__ import absolute_import

import mock
import os
import unittest

import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.resolver
import dns.rrset

from .. import Checker, QueryStrategyAll, exceptions
import dnsknife

here = os.path.dirname(__file__)

from . import fake_dns # patches for fake ten.pm entries

def inconsistent_at_ns(qname, qtype, ns, dnssec=False, subnet=None,
        prefixlen=None):
    return fake_dns.FakeFuture(str(qname), 'TXT', [str(ns)])


def consistent_at_ns(qname, qtype, ns, dnssec=False, subnet=None,
        prefixlen=None):
    return fake_dns.FakeFuture(str(qname), 'TXT', ['SameTXT'])


@mock.patch('dnsknife.resolver.ns_for', return_value=['before.ten.pm', 'after.ten.pm'])
@mock.patch('dnsknife.resolver.Resolver.query_at')
class TestChecker(unittest.TestCase):
    def test_txt(self, rmock, cmock):
        checker = Checker('ten.pm')
        rmock.return_value = fake_dns.FakeFuture('ten.pm', 'TXT', ['pouet'])
        self.assertEqual(checker.txt(), 'pouet')

    def test_query_nodnssec(self, rmock, cmock):
        Checker('ten.pm').query('ten.pm', 'A')
        cmock.assert_called_with('ten.pm', False)
        rmock.assert_any_call('ten.pm', 'A', '1.2.3.4', False)

    def test_query_dnssec(self, rmock, cmock):
        Checker('ten.pm', dnssec=True).query('ten.pm', 'A')
        cmock.assert_called_with('ten.pm', True)
        rmock.assert_any_call('ten.pm', 'A', '1.2.3.4', True)

    def test_query_relative(self, rmock, cmock):
        Checker('ten.pm').query_relative('www', 'A')
        rmock.assert_any_call(dns.name.from_text('www.ten.pm'),
                                 'A', '1.2.3.4', False)

    def test_has_txt_multivalues(self, rmock, cmock):
        rmock.return_value = fake_dns.FakeFuture('ten.pm', 'TXT', ['12345'])
        self.assertTrue(Checker('ten.pm').has_txt(['1', '2', '12345']))

    def test_has_no_txt(self, rmock, cmock):
        rmock.return_value = fake_dns.FakeFuture('ten.pm', 'TXT', ['12345'])
        self.assertFalse(Checker('ten.pm').has_txt('1234'))

    def test_has_txt(self, rmock, cmock):
        rmock.return_value = fake_dns.FakeFuture('ten.pm', 'TXT', ['1234'])
        self.assertTrue(Checker('ten.pm').has_txt('1234'))

    def test_has_txt_caseinsensitive(self, rmock, cmock):
        rmock.return_value = fake_dns.FakeFuture('ten.pm', 'TXT', ['1234ABC'])
        self.assertTrue(Checker('ten.pm').has_txt('1234abc'))

    def test_has_txt_casesensitive(self, rmock, cmock):
        rmock.return_value = fake_dns.FakeFuture('ten.pm', 'TXT', ['1234ABC'])
        self.assertFalse(Checker('ten.pm').has_txt('1234abc',
                                                   ignore_case=False))

    def test_challenge(self, rmock, cmok):
        chal = Checker('ten.pm').challenge('secret')
        rmock.return_value = fake_dns.FakeFuture('ten.pm', 'TXT', [chal.upper()])
        self.assertTrue(Checker('ten.pm').has_challenge('secret'))

    @mock.patch('time.time', return_value=1475608085)
    def test_challenge_from_past(self, tmok, rmock, cmok):
        rmock.return_value = fake_dns.FakeFuture('ten.pm', 'TXT',
                                        ['d7ab2f33a50b79b46f04d28ccebbf8425'
                                         '0584208b649def4f65d7ece28a2377b'])
        self.assertTrue(Checker('ten.pm').has_challenge('secret'))

    def test_mx(self, rmock, cmock):
        rmock.return_value = fake_dns.FakeFuture('ten.pm', 'MX', ['20 a.', '30 c.',
                                                         '10 b.'])
        self.assertEqual(['b.', 'a.', 'c.'], Checker('ten.pm').mx())

    def test_query_strategy_all_fail(self, rmock, cmock):
        rmock.side_effect = inconsistent_at_ns
        try:
            ret = Checker('ten.pm',
                query_strategy_class=QueryStrategyAll).txt()
            raise Exception('Expected NSDisagree, got %s' % ret)
        except exceptions.NSDisagree:
            pass

    def test_query_strategy_all_ok(self, rmock, cmock):
        rmock.side_effect = consistent_at_ns
        ret = Checker('ten.pm',
                query_strategy_class=QueryStrategyAll).txt()
        self.assertEqual('SameTXT', ret)
