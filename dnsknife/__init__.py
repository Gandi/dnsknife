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
import hashlib
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

from . import challenge
from . import dnssec
from . import exceptions
from . import monkeypatch  # noqa
from . import resolver
from .resolver import (set_nameservers, set_socks5_server,
                       query, set_edns0_size)  # noqa


__version__ = '0.12'


@contextlib.contextmanager
def as_dnssec(c):
    yield Checker(c.domain, dnssec=True, direct=c.direct,
                  errors=c.err_fn, nameservers=c.nameservers)


class TypeAware(object):
    """Convenient trait"""
    def partial_query(self, rtype):
        """Returns an answer object"""
        def query_with_default_name(name='', text=False):
            ans = self.query_relative(name, rtype)
            if not text:
                return ans
            return [rr.to_text() for rr in ans]
        return query_with_default_name

    def __getattribute__(self, name):
        if name in dns.rdatatype._by_text.keys():
            return self.partial_query(name)
        return super(TypeAware, self).__getattribute__(name)


class QueryStrategy:
    def __init__(self, checker):
        self.checker = checker


class QueryStrategyAny(QueryStrategy):
    """First NS with an answer that is good for us"""
    def query(self, name, rdtype, timeout):
        answers = []
        for ns in self.checker.ns:
            addr = random.choice(resolver.addresses([ns]))
            with resolver.Resolver(timeout) as r:
                answers.append(r.query_at(name, rdtype, addr,
                                          self.checker.dnssec))

        raised = None
        for ans in answers:
            try:
                return ans.get()
            except Exception as e:
                raised = e
                pass

        if raised:
            raise raised

def same_answer(a, b):
    #XXX find a better definition sometime
    res1 = []
    res2 = []

    try:
        res1 = a.get()
        res2 = b.get()
    except exceptions.NoAnswer:
        pass

    return [str(x) for x in sorted(res1)] == [str(x) for x in sorted(res2)]


class QueryStrategyAll(QueryStrategy):
    """Ensure answer is the same on all NS"""
    def query(self, name, rdtype, timeout):
        answers = []
        with resolver.Resolver(timeout) as r:
            for ns in self.checker.ns:
                addr = random.choice(resolver.addresses([ns]))
                answers.append(r.query_at(name, rdtype, addr,
                                          self.checker.dnssec))

        for a, b in zip(answers, answers[1:]):
            if not same_answer(a, b):
                raise exceptions.NSDisagree('%s != %s' % (a, b))

        return answers[0].get()


class Checker(TypeAware):
    def __init__(self, domain, dnssec=False, direct=True,
                 errors=None, nameservers=None,
                 query_strategy_class=QueryStrategyAny):
        self.domain = domain
        self.dnssec = dnssec
        self.direct = direct
        self.err_fn = errors
        self.nameservers = nameservers
        self.query_strategy_class = query_strategy_class
        self.query_strategy = query_strategy_class(self)
        self._ns = None

    def with_query_strategy(self, qs_class):
        return Checker(self.domain, self.dnssec, self.direct,
                self.err_fn, self.nameservers, qs_class)

    def at_parent(self):
        ##XXX maybe use a strategy instead - this is hackish
        parent = dns.name.from_text(self.domain).parent().to_text()
        parent_ns = Checker(parent).ns
        new_checker = Checker(self.domain, self.dnssec, self.direct,
                self.err_fn, self.nameservers, self.query_strategy_class)

        new_checker._ns = parent_ns
        return new_checker

    @property
    def ns(self):
        if not self._ns:
            self._ns = resolver.ns_for(self.domain, self.dnssec)
        return self._ns

    def query(self, name, rdtype, timeout=2):
        """Lookup."""
        if self.direct:
            return self.query_strategy.query(name, rdtype, timeout)
        return resolver.query(name, rdtype, self.dnssec)

    def query_relative(self, name, rdtype):
        """Lookup, relative to domain"""
        qname = dns.name.from_text(name, dns.name.from_text(self.domain))
        return self.query(qname, rdtype)

    def notify_error(self, exc):
        if self.err_fn:
            self.err_fn(exc)

    def txt(self, name=''):
        """Return the txt for name under zone, values joined
        as a string, each record separated by a newline"""
        try:
            resp = self.query_relative(name, dns.rdatatype.TXT)
            def strvalue(r):
                return ''.join([x.decode() for x in r.strings])
            return '\n'.join(strvalue(r) for r in resp
                             if r.rdtype == dns.rdatatype.TXT)
        except (dns.resolver.NoAnswer, exceptions.BadRcode):
            pass

    def has_txt(self, values, name='@', ignore_case=True):
        """Find if one of the specified TXT record in zone exists
        at a given name. Eventually ignore case."""

        if isinstance(values, str):
            values = [values]

        if ignore_case:
            def equals(a, b):
                return a.lower() == b.lower()
        else:
            def equals(a, b):
                return a == b

        try:
            resp = self.txt(name)
            for txt in resp.split('\n'):
                if any(equals(txt, good) for good in values):
                    return True
        except (Exception) as e:
            self.notify_error(e)

        return False

    def challenge(self, secret, validity=86400):
        return challenge.valid_tokens(self.domain, secret, validity)[-1]

    def has_challenge(self, secret, name='@', validity=86400):
        valid = challenge.valid_tokens(self.domain, secret, validity)
        return self.has_txt(valid, name)

    def _uri_to_txt(self, ans):
        txt = ans.rrset[0].target

        # Workaround URI spec change
        return txt[txt.index('http'):]

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
        txt = self.txt()
        if txt:
            for rec in txt.split("\n"):        
                if rec.startswith('v=spf'):
                    return rec

    def spf(self):
        try:
            req = self.query_relative('', 'SPF')
            return req.rrset[0].to_text()
        except dns.resolver.NoAnswer:
            return self.txt_spf()

    def tpda_endpoint(self, name, timeout=1):
        """Return the endpoint according to this domain DNS operator
        setup. (Lookup _tpda service name as an URI on each NS)."""
        answers = []

        with resolver.Resolver(timeout=timeout) as r:
            for ns in self.ns:
                qname = '{}._tpda._tcp.{}'.format(name, ns)
                if self.direct:
                    answers.append(r.query_at(qname, 'URI',
                                   resolver.ns_for(ns)[0]))
                else:
                    answers.append(r.query(qname, 'URI'))

        for answer in answers:
            try:
                return self._uri_to_txt(answer.get())
            except:
                pass

    def openpgp(self, localpart):
        """Look for OPENPGPKEY record for local part."""
        localpart = localpart.lower().encode('utf8')
        hashed = hashlib.sha256(localpart).hexdigest()[:56]
        return self.OPENPGPKEY('{}._openpgpkey'.format(hashed))

    def cdnskey(self):
        """ 1. All NS should agree on the CDS set
                -> Ensured via QueryStrategyAll
            2. Presence of 0 algorithm means remove everything
            2. DNSKEY RRSET should include the appropriate keys
            4. Older CDS should not overwrite newer DATA (DS)
               RFC states that. I don't get it.

            5. This should be DNSSEC validated - up to the caller here
               to properly set dnssec validation if needed. That allows
               reporting/.. and initial DS install.
        """
        # 1. All NS have the same set - check CDS records
        # First, raise if no DNSKEY records
        dnskeys = self.query(self.domain, 'DNSKEY')
        ckeys = []
        cds = []
        try:
            cds = self.query(self.domain, 'CDS')
            ckeys = self.query(self.domain, 'CDNSKEY')
        except dns.resolver.NoAnswer:
            ckeys = [dnssec.matching_key(dnskeys, ds) for ds in cds]

        if not all(ckeys):
            # If any None in there, we have non matching keys
            failed = [ds for ds in cds if not dnssec.matching_key(dnskeys, ds)]
            raise exceptions.BadCDNSKEY('{} not in '
                                        'DNSKEY RRSET'.format(failed))

        # 2. 0 is a deletion, but don't allow more than one key
        # in that case
        if any(key.algorithm == 0 for key in ckeys):
            if len(ckeys) == 1:
                # Special case delete
                raise exceptions.DeleteDS
            else:
                raise exceptions.BadCDNSKEY('Alg0 and multiple keys found')


        # 3. Double check the new key is also signing the zone,
        # otherwise pushing the DS would break things
        for key in ckeys:
            sig, errs = dnssec.signed_by(dnskeys, key)
            if not sig:
                errstr = ('{} did not sign '
                        'DNSKEY RR (errs:{})'.format(key, errs))
                raise exceptions.BadCDNSKEY(errstr)

        return ckeys
