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

from . import fake_dns # patches for fake ten.pm entries

def empty_cds_query(qname, qtype, ns, dnssec=False):
    if qtype == 'DNSKEY':
        return fake_dns.FakeFuture(str(qname), 'DNSKEY',
                ['256 3 8 AwEAAcNVRzn98wLlO8nyh6eppxHAKEJ/XrSDdFjuH84K+Gi3w7wiMJ5T R0yZSTjBsKkuwf8nrwTFiS5uTygdrh1Z4+RRm2uSxGdm4pgu0G9GbAkHoA5iIRW8w9MzivFFZmXwMtohz47merOvFuotXQgY2RBgLAkSs/4GJwKH/awer3iIBt1EapzmvtvK5VVtI7a5RmgtQmjMwlgxPDY9qVFgnbsk9OypgZqscICM0DYe8XRrz7t/8EjfoK2WtfDzTyiM14eLZF7y043GRsZBT/JRmcLKAQqyFxEV2CxJHAeJ7TfhSS+T8s7fECYRxzlHfT9XH0mkXYXOmX27LIR6h7u1cns='])
    elif qtype in ('CDS', 'CDNSKEY'):
        return fake_dns.FakeFutureNoAnswer()

def valid_cds_query(qname, qtype, ns, dnssec=False):
    if qtype == 'CDS':
        return fake_dns.FakeFuture(str(qname), 'CDS', ['6825 13 2 7f71d1f62ceb0a7f18f680282c1f9f36da814c5eea0e25cca27963a2b07affdb'])
    #, '6825 13 1 22d0b768dfca07caf2ec3ea47ef6ac0f6318e9a6'])
    elif qtype == 'DNSKEY':
        return fake_dns.FakeFuture(str(qname), 'DNSKEY', ["257 3 13 DFRmw9H+ClMblCxRqLOo3/OHOiWs9QK4 1FVSYK0Zqcin9l25Wp2bW7IyzKMatUgu pnr3O19uiZPXWqTPoY9Q8A=="], "DNSKEY 13 2 10800 20180920000000 20180830000000 6825 rdap.lol. 9Se5sXaZCEa3l1obJ9mz5mkrrFl5z5Fk LKM6jGwACJNOy9xuipMYXzXpBP8jb4iq bkmBUH6ZaF19Zz6gvzvhRg==")
    else:
        return fake_dns.FakeFutureNoAnswer()

def unsigned_cds_query(qname, qtype, ns, dnssec=False):
    if qtype == 'CDS':
        return fake_dns.FakeFuture(str(qname), 'CDS', ['6825 13 2 7f71d1f62ceb0a7f18f680282c1f9f36da814c5eea0e25cca27963a2b07affdb'])
    #, '6825 13 1 22d0b768dfca07caf2ec3ea47ef6ac0f6318e9a6'])
    elif qtype == 'DNSKEY':
        return fake_dns.FakeFuture(str(qname), 'DNSKEY', ["257 3 13 DFRmw9H+ClMblCxRqLOo3/OHOiWs9QK4 1FVSYK0Zqcin9l25Wp2bW7IyzKMatUgu pnr3O19uiZPXWqTPoY9Q8A=="])
    else:
        return fake_dns.FakeFutureNoAnswer()



@mock.patch('dnsknife.resolver.ns_for', return_value=['before.ten.pm', 'after.ten.pm'])
@mock.patch('dnsknife.resolver.Resolver.query_at')
class TestChecker(unittest.TestCase):
    def test_no_cds(self, rmock, cmock):
        rmock.side_effect = empty_cds_query
        ret = Checker('ten.pm',
                query_strategy_class=QueryStrategyAll).cdnskey()
        self.assertEqual([], ret)

    def test_cds_not_signed(self, rmock, cmock):
        rmock.side_effect = unsigned_cds_query
        self.assertRaises(exceptions.BadCDNSKEY, Checker('rdap.lol.',
                query_strategy_class=QueryStrategyAll).cdnskey)

    def test_cds_valid(self, rmock, cmock):
        rmock.side_effect = valid_cds_query
        with mock.patch('time.time', return_value=1536464380) as mock_time:
            ret = Checker('rdap.lol.',
                    query_strategy_class=QueryStrategyAll).cdnskey()
            self.assertEqual('257 3 13 DFRmw9H+ClMblCxRqLOo3/OHOiWs9QK4 1FVSYK0Zqcin9l25Wp2bW7IyzKMatUgu pnr3O19uiZPXWqTPoY9Q8A==', str(ret[0]))
