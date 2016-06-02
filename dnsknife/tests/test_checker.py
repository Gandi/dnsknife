from __future__ import absolute_import

import mock
import os
import unittest

import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.resolver
import dns.rrset

from .. import Checker

here = os.path.dirname(__file__)


def fake_answer(name, rdtype, rvalues):
    name = dns.name.from_text(name)
    rdtype = dns.rdatatype.from_text(rdtype)
    msg = dns.message.make_query(name, rdtype, dns.rdataclass.IN)
    resp = dns.message.make_response(msg)
    rrset = resp.find_rrset(resp.answer, name, dns.rdataclass.IN, rdtype,
                            create=True)
    for rvalue in rvalues:
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, rdtype, rvalue))
    return dns.resolver.Answer(name, rdtype, dns.rdataclass.IN, resp)


class FakeFuture:
    def __init__(self, name, rdtype, rvalues):
        self.name = name
        self.rdtype = rdtype
        self.rvalues = rvalues

    def get(self):
        return fake_answer(self.name, self.rdtype, self.rvalues)


@mock.patch('dnsknife.resolver.ns_for', return_value=['1.2.3.4'])
@mock.patch('dnsknife.resolver.Resolver.query_at')
class TestChecker(unittest.TestCase):
    def test_txt(self, rmock, cmock):
        checker = Checker('ten.pm')
        rmock.return_value = FakeFuture('ten.pm', 'TXT', ['pouet'])
        self.assertEqual(checker.txt(), 'pouet')

    def test_query_nodnssec(self, rmock, cmock):
        Checker('ten.pm').query('ten.pm', 'A')
        cmock.assert_called_with('ten.pm', False)
        rmock.assert_called_with('ten.pm', 'A', '1.2.3.4', False)

    def test_query_dnssec(self, rmock, cmock):
        Checker('ten.pm', dnssec=True).query('ten.pm', 'A')
        cmock.assert_called_with('ten.pm', True)
        rmock.assert_called_with('ten.pm', 'A', '1.2.3.4', True)

    def test_query_relative(self, rmock, cmock):
        Checker('ten.pm').query_relative('www', 'A')
        rmock.assert_called_with(dns.name.from_text('www.ten.pm'),
                                 'A', '1.2.3.4', False)

    def test_has_no_txt(self, rmock, cmock):
        rmock.return_value = FakeFuture('ten.pm', 'TXT', ['12345'])
        self.assertFalse(Checker('ten.pm').has_txt('1234', ['www']))

    def test_has_txt(self, rmock, cmock):
        rmock.return_value = FakeFuture('ten.pm', 'TXT', ['1234'])
        self.assertTrue(Checker('ten.pm').has_txt('1234', ['www']))

    def test_has_txt_caseinsensitive(self, rmock, cmock):
        rmock.return_value = FakeFuture('ten.pm', 'TXT', ['1234ABC'])
        self.assertTrue(Checker('ten.pm').has_txt('1234abc', ['www']))

    def test_has_txt_casesensitive(self, rmock, cmock):
        rmock.return_value = FakeFuture('ten.pm', 'TXT', ['1234ABC'])
        self.assertFalse(Checker('ten.pm').has_txt('1234abc', ['www'],
                                                   ignore_case=False))

    def test_mx(self, rmock, cmock):
        rmock.return_value = FakeFuture('ten.pm', 'MX', ['20 a.', '30 c.',
                                                         '10 b.'])
        self.assertEqual(['b.', 'a.', 'c.'], Checker('ten.pm').mx())
