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
import socket

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
try:
    import socks
    __socks_available = True
except ImportError:
    __socks_available = False


from . import async
from . import exceptions
from . import monkeypatch  # noqa


__version__ = '0.2'

_config = {
    'resolver': dns.resolver.Resolver(),
    'socks': None
}


def set_nameservers(ns):
    _config['resolver'].nameservers = ns


def set_socks5_server(addr, port=1080, username=None, password=None):
    if not __socks_available:
        raise ImportError('No module named socks')

    socks.set_default_proxy(socks.SOCKS5, addr, port, False, username,
                            password)
    _config['socks'] = socks


def query(name, rdtype, dnssec=False):
    """Lookup. Using the locally configured resolvers
    by default. Eventually using the local NS AD bit as a trust source."""
    # Query for our name, let NXDOMAIN raise
    res = _config['resolver']
    if dnssec:
        res.use_edns(0, dns.flags.DO, 0)

    # Convenience for external callers
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)

    answer = res.query(name, rdtype)

    # Double check we have DNSSEC validation
    if dnssec:
        if not answer.response.flags & dns.flags.AD:
            raise exceptions.NoDNSSEC

    return answer


def ns_addr_insecure(nameserver):
    """Find the nameserver's possible IP addresses. No DNSSEC
    is required here, we'll just validate the end result."""
    ans = []
    for family, socktype, proto, name, sockaddr in \
            socket.getaddrinfo(nameserver, 53):
        if proto == socket.IPPROTO_UDP:
            ans.append(sockaddr[0])
    if len(ans) == 0:
        raise exceptions.NsLookupError(nameserver)
    return ans


def rrset_rrsig(response):
    """Split and return rrsig and rrset from answer"""
    rrsig = response.find_rrset(response.answer, response.question[0].name,
                                dns.rdataclass.IN, dns.rdatatype.RRSIG,
                                response.question[0].rdtype)
    rrset = response.find_rrset(response.answer, response.question[0].name,
                                dns.rdataclass.IN, response.question[0].rdtype)

    return rrset, rrsig


def signers(answer):
    """Takes a dns.resolver.Answer, and return signer
    names and key_tags. Check that signers are allowed
    to sign names.

        {'signer': [keytag, keytag], ..}

    """
    rrset, rrsig = rrset_rrsig(answer.response)
    qname = answer.response.question[0].name

    signer_names = set(sig.signer for sig in rrsig)
    if not all([qname.is_subdomain(sn) for sn in signer_names]):
        raise exceptions.BadSignerName

    ret = {}
    for sig in rrsig:
        ret.setdefault(sig.signer, []).append(sig.key_tag)

    return ret


def signed_by(answer, dnskey):
    """Checks that a given dns.resolver.Answer has been signed
    by the given dns Key object."""
    rrset, rrsig = rrset_rrsig(answer.response)

    for sig in rrsig:
        if sig.key_tag == dns.dnssec.key_id(dnskey):
            try:
                dns.dnssec.validate_rrsig(rrset, sig, {sig.signer: [dnskey]})
                return True
            except:
                pass
    return False


def trusted(answer):
    """Check if one signer in the dns.resolver.Answer is trusted"""
    for signer in signers(answer).keys():
        keyans = query(signer, dns.rdatatype.DNSKEY)
        for key in keyans:
            if signed_by(answer, key):
                return True


@contextlib.contextmanager
def dnssec(c):
    yield Checker(c.domain, dnssec=True, direct=c.direct,
                  errors=c.err_fn, nameservers=c.nameservers)


class Checker(object):

    def __init__(self, domain, dnssec=False, direct=True,
                 errors=None, nameservers=None):
        self.domain = domain
        self.dnssec = dnssec
        self.direct = direct
        self.err_fn = errors
        self.nameservers = nameservers

    @property
    def ns(self):
        if not self.nameservers:
            return [ns.target.to_text() for ns in
                    query(self.domain, dns.rdatatype.NS,
                    self.dnssec).rrset]

        return self.nameservers

    def set_nameservers(self, ns):
        self.nameservers = ns

    def query_at(self, qname, rdtype, nameserver, timeout=2):
        """Lookup, but explicitely sends a packet to the selected
        nameserver."""
        rdclass = dns.rdataclass.IN

        # Convenience for external callers
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        if isinstance(qname, str):
            qname = dns.name.from_text(qname)

        req = dns.message.make_query(qname, rdtype, rdclass)
        if self.dnssec:
            req.use_edns(0, dns.flags.DO, 0)

        for addr in ns_addr_insecure(nameserver):
            try:
                if _config['socks']:
                    old_socket = socket.socket
                    dns.query.socket.socket = _config['socks'].socksocket

                ans = dns.query.udp(req, addr, timeout, 53)
                if ans.flags & dns.flags.TC:
                    ans = dns.query.tcp(req, addr, timeout, 53)
                if ans.rcode() != dns.rcode.NOERROR:
                    raise exceptions.BadRcode(dns.rcode.to_text(ans.rcode()))
                answer = dns.resolver.Answer(qname, rdtype, rdclass, ans)
                if not self.dnssec or trusted(answer):
                    return answer
                if self.dnssec:
                    raise exceptions.NoDNSSEC
            except (dns.exception.Timeout, socket.error) as e:
                self.notify_error(e)
                continue
            finally:
                if _config['socks']:
                    dns.query.socket.socket = old_socket
        raise exceptions.NsLookupError('no working dns used')

    def query(self, name, rdtype):
        """Lookup."""
        if self.direct:
            raised = None
            with async.Wrapper(self) as aw:
                for ns in self.ns:
                    aw.query_at(name, rdtype, ns)

                for res in aw.get_all():
                    if isinstance(res, Exception):
                        raised = res
                    else:
                        return res

            if raised:
                raise raised

        return query(name, rdtype, self.dnssec)

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
                sorted(mx_set, None, lambda rr: rr.preference)]

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
        with async.Wrapper(self) as aw:
            for ns in self.ns:
                qname = '{}._tpda._tcp.{}'.format(name, ns)
                aw.query_at(qname, 'URI', ns)
            for ans in aw.get_all():
                if not isinstance(ans, Exception):
                    return self._uri_to_txt(ans)

    def _cdnskey(self):
        """ 1. All nameservers should agree on the CDNSKEY set
            2. The CDNSKEY should already be signing the DNSKEY RRSET
            3. Presence of 0 algorithm means remove everything. Cannot
               be mixed with other valid CDNSKEYs.
            4. Older CDNSKEY should not overwrite newer DATA (DS)
               RFC states that. I don't get it.
            5. This should be DNSSEC validated. Yep.
        """
        cds_rrset = None
        for ns in self.ns:
            cds = self.query_at(self.domain, dns.rdatatype.CDNSKEY, ns)
            dnskeys = self.query_at(self.domain, dns.rdatatype.DNSKEY, ns)
            if cds_rrset is None:
                cds_rrset = set(cds)

            # 1.
            if set(cds) != cds_rrset:
                errstr = ('{} disagrees on CDNSKEY '
                          'RRSet ({}!={})'.format(ns, set(cds), cds_rrset))
                raise exceptions.BadCDNSKEY(errstr)

            # 2.
            for key in cds:
                if not signed_by(dnskeys, key):
                    errstr = ('{} did not sign '
                              'DNSKEY RR'.format(dns.dnssec.key_id(key)))
                    raise exceptions.BadCDNSKEY(errstr)

            # 3.
            if any(key.algorithm == 0 for key in cds):
                if len(cds) == 1:
                    # Special case delete
                    raise exceptions.DeleteDS
                else:
                    raise exceptions.BadCDNSKEY('Alg0 and other keys found')

        return cds_rrset

    def cdnskey(self):
        """Wrapper - enforce dnssec usage"""
        with dnssec(self) as sec:
            return sec._cdnskey()
