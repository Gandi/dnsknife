from __future__ import absolute_import

import dnsknife

import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.resolver
import dns.rrset


def fake_answer(name, rdtype, rvalues, sig=None):
    name = dns.name.from_text(name)
    rdtype = dns.rdatatype.from_text(rdtype)
    msg = dns.message.make_query(name, rdtype, dns.rdataclass.IN)
    resp = dns.message.make_response(msg)
    rrset = resp.find_rrset(resp.answer, name, dns.rdataclass.IN, rdtype,
                            create=True)
    for rvalue in rvalues:
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, rdtype, rvalue))

    if sig:
        rrset = resp.find_rrset(resp.answer, name, dns.rdataclass.IN,
                dns.rdatatype.RRSIG, rdtype, create=True)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN,
                dns.rdatatype.RRSIG, sig))
    return dns.resolver.Answer(name, rdtype, dns.rdataclass.IN, resp)


class FakeFuture:
    def __init__(self, name, rdtype, rvalues, sig=None):
        self.name = name
        self.rdtype = rdtype
        self.rvalues = rvalues
        self.sig = sig

    def get(self):
        return fake_answer(self.name, self.rdtype, self.rvalues, self.sig)


class FakeFutureNoAnswer:
    def get(self):
        raise dns.resolver.NoAnswer

def fake_addr(names):
    n_to_ad = {'before.ten.pm': '1.2.3.4',
               'after.ten.pm': '1.2.3.5',
               '*': '1.2.3.6'}
    return [n_to_ad.get(x, n_to_ad['*']) for x in names]

dnsknife.resolver.addresses = fake_addr
