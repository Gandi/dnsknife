"""
Implements various DNS checks with potential DNSSEC
validation, bypassing local cache for the cases where
one needs immediate revalidation or per DNS configurations.

Needs DNSSEC-aware resolver to have a chance to grab domain
cached trust anchors and verify keys.

For now this requires that a cached DNSKEY is still
signing domain data.

Optional support and dependency on PySocks for socks5
proxy support.
"""

from __future__ import absolute_import

import contextlib
import random

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from . import dnssec
from . import exceptions
from . import monkeypatch  # noqa
from . import resolver
from .resolver import set_nameservers, set_socks5_server, query  # noqa


__version__ = '0.5'


@contextlib.contextmanager
def as_dnssec(c):
    yield Checker(c.domain, dnssec=True, direct=c.direct,
                  errors=c.err_fn, nameservers=c.nameservers)


class Checker(object):
    def __init__(self, domain, dnssec=False, direct=True,
                 errors=None, nameservers=None):
        self.domain = domain
        self.dnssec = dnssec
        self.direct = direct
        self.err_fn = errors
        self.ns_addrs = nameservers or resolver.ns_for(self.domain, self.dnssec)

    def set_nameservers(self, ns):
        self.ns_addrs = ns

    def query_at(self, qname, rdtype, nameserver, timeout=2):
        """Lookup, but explicitely sends a packet to the selected
        nameserver."""
        with resolver.Resolver(timeout) as r:
            ans = r.query_at(qname, rdtype, nameserver, self.dnssec)
        return ans.get()

    def query(self, name, rdtype):
        """Lookup."""
        if self.direct:
            raised = None
            for ns in self.ns_addrs:
                try:
                    return self.query_at(name, rdtype, ns)
                except Exception as e:
                    raised = e
                    pass

            if raised:
                raise raised

        return resolver.query(name, rdtype, self.dnssec)

    def query_relative(self, name, rdtype):
        """Lookup, relative to domain"""
        qname = dns.name.from_text(name, dns.name.from_text(self.domain))
        return self.query(qname, rdtype)

    def notify_error(self, exc):
        if self.err_fn:
            self.err_fn(exc)

    def ns(self):
        """Return the nameservers (hostnames) for this domain"""
        return [rrset.target.to_text() for rrset in
                self.query_relative('', 'NS').rrset]

    def random_ns_addr(self):
        return random.sample(self.ns_addrs, 1)[0]

    def txt(self, name=''):
        """Return the txt for name under zone, values joined
        as a string, each record separated by a newline"""
        resp = self.query_relative(name, dns.rdatatype.TXT)
        return '\n'.join(''.join(r.strings) for r in resp
                         if r.rdtype == dns.rdatatype.TXT)

    def has_txt(self, value, also_check=None, ignore_case=True):
        """Find if the specified TXT record in zone exists
        at given names (default @, also_check list of additional
        names). Eventually ignore case."""
        if not also_check:
            also_check = []

        if ignore_case:
            def equals(a, b):
                return a.lower() == b.lower()
        else:
            def equals(a, b):
                return a == b

        for name in [''] + also_check:
            try:
                resp = self.query_relative(name, dns.rdatatype.TXT)
                for rr in resp:
                    if any(equals(value, v) for v in rr.strings):
                        return True
            except (Exception) as e:
                self.notify_error(e)
        return False

    def _uri_to_txt(self, ans):
        # XXX Might use target once dnspython follows URI RFC
        return ans.rrset[0].data[4:]

    def uri(self, name, relative=True):
        """Return the published URI"""
        if relative:
            ans = self.query_relative(name, dns.rdatatype.URI)
        else:
            ans = self.query(name, dns.rdatatype.URI)
        return self._uri_to_txt(ans)

    def mx(self, name=''):
        """Return the mx set for the domain"""
        try:
            mx_set = [rr for rr in self.query_relative(name, 'MX') if
                      rr.rdtype == dns.rdatatype.MX]
        except dns.resolver.NoAnswer:
            return []

        return [rr.exchange.to_text() for rr in
                sorted(mx_set, key=lambda rr: rr.preference)]

    def txt_spf(self):
        """Return first TXT/spf record for domain"""
        try:
            for rec in self.txt():
                if rec.startswith('v=spf'):
                    return rec
        except dns.resolver.NoAnswer:
            pass

    def spf(self):
        try:
            req = self.query_relative('', 'SPF')
            return req.rrset[0].to_text()
        except dns.resolver.NoAnswer:
            return self.txt_spf()

    def tpda_endpoint(self, name):
        """Return the endpoint according to this domain DNS operator
        setup. (Lookup _tpda service name as an URI on each NS)."""
        answers = []
        with resolver.Resolver() as r:
            for ns in self.ns():
                qname = '{}._tpda._tcp.{}'.format(name, ns)
                answers.append(r.query_at(qname, 'URI', self.random_ns_addr()))

        for answer in answers:
            try:
                return self._uri_to_txt(answer.get())
            except:
                pass

    def cdnskey(self):
        """ 1. All nameservers should agree on the CDNSKEY set
            2. The CDNSKEY should already be signing the DNSKEY RRSET
            3. Presence of 0 algorithm means remove everything. Cannot
               be mixed with other valid CDNSKEYs.
            4. Older CDNSKEY should not overwrite newer DATA (DS)
               RFC states that. I don't get it.
            5. This should be DNSSEC validated. Yep.
        """
        cds = {}
        dnskeys = {}

        cds_rrset = None

        with resolver.Resolver() as r:
            for ns in self.ns_addrs:
                cds[ns] = r.query_at(self.domain, dns.rdatatype.CDNSKEY,
                                     ns, True)
                dnskeys[ns] = r.query_at(self.domain, dns.rdatatype.DNSKEY,
                                         ns, True)

        for ns in self.ns_addrs:
            # 1.
            cds[ns] = cds[ns].get()
            dnskeys[ns] = dnskeys[ns].get()
            if cds_rrset:
                if set(cds[ns]) != cds_rrset:
                    errstr = ('{} disagrees on CDNSKEY '
                              'RRSet ({}!={})'.format(ns, set(cds), cds_rrset))
                    raise exceptions.BadCDNSKEY(errstr)
            cds_rrset = set(cds[ns])

            # 2.
            for key in cds[ns]:
                if not dnssec.signed_by(dnskeys[ns], key):
                    errstr = ('{} did not sign '
                              'DNSKEY RR'.format(dns.dnssec.key_id(key)))
                    raise exceptions.BadCDNSKEY(errstr)

        for ns in self.ns_addrs:
            # 3.
            if any(key.algorithm == 0 for key in cds[ns]):
                if len(cds[ns]) == 1:
                    # Special case delete
                    raise exceptions.DeleteDS
                else:
                    raise exceptions.BadCDNSKEY('Alg0 and other keys found')

        return cds_rrset
