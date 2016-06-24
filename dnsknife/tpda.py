from __future__ import absolute_import, print_function

import base64
import datetime
import requests
from six.moves.urllib import parse

# TODO: improve key storage/publication
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from . import Checker
from . import exceptions


def _qsl_get_one(qstring, param):
    """Return one unique param from query string"""
    args = parse.parse_qsl(qstring)
    sigvals = [arg[1] for arg in args if arg[0] == param]

    if len(sigvals) != 1:
        raise exceptions.InvalidArgument(param)

    return sigvals[0]



# Uses RDAP
class ServiceLocator:

    """Uses RDAP to find the registrar for a domain,
    registrar service URLs, or third party DNS operator
    service URLs"""

    def __init__(self, baseURI, timeout=5):
        self.baseURI = baseURI
        self.timeout = timeout

    def query(self, domain):
        uri = '{}/domain/{}'.format(self.baseURI, domain)
        r = requests.get(uri, timeout=self.timeout)
        if r.status_code == 404:
            raise exceptions.DomainNotFound()
        if r.status_code == 200:
            return r.json()
        return {}

    def endpoint(self, domain, service):
        d = self.query(domain)
        if not d.get('links'):
            raise exceptions.TPDANotEnabled('no tpda endpoints on registrar')

        for link in d['links']:
            if link.get('rel', '').endswith('/tpda/{}'.format(service)):
                return link['href']

        raise exceptions.ServiceNotPresent(
                'service not found')


# XXX Well.
STATIC_RDAP_SERVICES = [
    'http://rdap.gandi.net'
]


class Client:

    """
    TPDA Client for third party service providers.
    Example usage:

    (Generate "test.key" or import it from nameserver)

    from dnsknife import tpda
    tpda.Client('thirdparty.example.com','test.key').nameservers_uri(
               'client.example.com', ['ns1.example.com','ns2.example.com'])
    """

    def __init__(self, domain, key, lease_time=3600, override_uri=None):
        """Initialize a TPDA client. `domain` refers to the client
        domain where the _tpda DNSKEY record should be published.
        `key` is a local path to access this same private key.
        `lease_time` is the signature expiration delay"""
        self.domain = domain
        self.key = RSA.importKey(open(key).read())
        self.lease_time = lease_time
        self.override_uri = override_uri

    def key_txt(self):
        """Return text of key"""
        return base64.b64encode(self.key.publickey().exportKey('DER'))\
                     .decode('ascii')

    def txt_record_of_key(self):
        """Dumps RSA key as a TXT record"""
        txt = self.key_txt()
        strings = ['"{}"'.format(txt[i:i + 65])
                   for i in range(0, len(txt), 65)]
        return 'IN TXT {}'.format(" ".join(strings))

    def params_for_domain(self, domain):
        """Return the mandatory, common 3rd party parameters for this
        user's domain"""
        exp = (datetime.datetime.utcnow() + datetime.timedelta(
            seconds=self.lease_time)).strftime('%Y%m%d%H%M%S')

        return (('source', self.domain), ('domain', domain),
                ('expires', exp))

    def nameservers_uri(self, domain, ns_list):
        """Return the full signed URI to access this domain operator nameservers
        setup service, if available. XXX: Implement glue record/ipv4/ipv6
        management in here too.

        For now `ns_list` is simply a list of strings.
        """
        params = self.params_for_domain(domain)
        for ns in ns_list:
            params += ('ns', ns),

        return self.sign_for_domain(domain, 'nameservers', params)

    def record_uri(self, domain, records):
        """Return the full signed URI to access this domain operator record
        service, if available. records should be a tuple of (name, type, value)
        tuples such as:

            uri = domain.record_uri('example.com', (('@', 'A', '192.0.2.1'),
                ('www', 'CNAME', '@')))
        """

        params = self.params_for_domain(domain)
        for rname, rtype, rvalue in records:
            params += ('name', rname), ('type', rtype), ('value', rvalue)

        return self.sign_for_domain(domain, 'record', params)

    def dnssec_uri(self, domain, algorithm, pubkey, flags=257):
        """Return the full signed URI to access this domain operator dnssec
        first setup service and install given key, if available."""

        params = self.params_for_domain(domain)
        params += ('algorithm', algorithm), ('pubkey', pubkey), \
                  ('flags', flags)

        return self.sign_for_domain(domain, 'dnssec', params)

    def website_uri(self, domain, ipv4=None, ipv6=None, cname=None):
        """Return the full signed URI to change this domain web configuration
        as per spec. ipv4/v6 are used to setup zone apex A/AAAA records. CNAME
        can be used to setup 'WWW' alias."""

        params = self.params_for_domain(domain)
        for ipv4 in ipv4 or []:
            params += ('ipv4', ipv4),

        for ipv6 in ipv6 or []:
            params += ('ipv6', ipv6),

        if cname:
            params += ('cname', cname),

        return self.sign_for_domain(domain, 'website', params)

    def email_uri(self, domain, mx_list=[]):
        """Return the full signed URI to change this domain mail configuration
        as per spec. Format for each MX entry is "<priority> <exchange.>" as
        in MX records"""

        params = self.params_for_domain(domain)

        for m in mx_list:
            params += ('mx', m),

        return self.sign_for_domain(domain, 'email', params)

    def sign_for_domain(self, domain, service, params):
        def find(domain, service):
            for rdap in STATIC_RDAP_SERVICES:
                try:
                    return ServiceLocator(rdap).endpoint(domain, service)
                except Exception as e:
                    print(e)

        if not self.override_uri:
            base_url = find(domain, service)
        else:
            base_url = self.override_uri

        if not base_url:
            raise exceptions.NoTPDA

        uri = u'{}?{}'.format(base_url, parse.urlencode(params, True))

        signer = PKCS1_v1_5.new(self.key)
        digest = SHA256.new()
        digest.update(uri.encode('ascii'))

        sig = base64.b64encode(signer.sign(digest))
        return '{}&{}'.format(uri, parse.urlencode({'signature': sig}))

## Implementation of URL parsing
class Completed(Exception):
    pass


class Param:
    attrs = ()
    multiple = ()
    optional = ()
    subparams = ()

    def __init__(self, parent=None):
        self.state = {}
        self.parent = parent

    def wants(self, name):
        if name in self.attrs + self.optional:
            if name not in self.state or name in self.multiple:
                return self

        for sub in self.subparams:
            p = sub(self)
            if name in p.attrs:
                self.state.setdefault(p.name, []).append(p)
                return p

        if self.parent:
            return self.parent.wants(name)

    def add(self, name, value):
        if name in self.multiple:
            self.state.setdefault(name, []).append(value)
        else:
            self.state[name] = value

    def complete(self):
        return all(x in self.state for x in self.attrs)

    def as_dict(self):
        def as_dict(what):
            if isinstance(what, list):
                return list(as_dict(w) for w in what)
            elif isinstance(what, dict):
                return dict((k, as_dict(v)) for k,v in what.items())
            elif isinstance(what, Param):
                return what.as_dict()
            else:
                return what
        return as_dict(self.state)


class NsParam(Param):
    name = 'nameservers'
    attrs = ('ns',)
    optional = ('ipv4', 'ipv6')
    multiple = ('ipv4', 'ipv6')


class RecordParam(Param):
    name = 'record'
    attrs = ('name', 'type', 'value')


class DNSSECParam(Param):
    name = 'dnssec'
    attrs = ('algorithm', 'pubkey', 'flags')


class EmailParamMX(Param):
    name = 'email'
    attrs = ('mx',)


class EmailParamImapSvc(Param):
    name = 'email'
    attrs = ('imaps',)


class EmailParamPop3Svc(Param):
    name = 'email'
    attrs = ('pop3s',)


class EmailParamCaldavSvc(Param):
    name = 'email'
    attrs = ('caldav',)


class WebsiteParamIP(Param):
    name = 'website'
    attrs = ('ipv4',)


class WebsiteParamIPv6(Param):
    name = 'website'
    attrs = ('ipv6',)


class WebsiteParamCNAME(Param):
    name = 'website'
    attrs  = ('cname',)


class TPDAParam(Param):
    attrs = ('domain',)
    optional = ('source', 'expires', 'signature', 'redirect')
    subparams = (NsParam, RecordParam, DNSSECParam, EmailParamMX,
                 EmailParamImapSvc, EmailParamPop3Svc,
                 EmailParamCaldavSvc, WebsiteParamIP,
                 WebsiteParamIPv6, WebsiteParamCNAME)


class Params:
    """Takes a list of (name, value) and convert into
    a comprehensive tpda parameter dict.

    With a multidict, items()
    with an URL, parse_qsl(query)
    """
    def __init__(self, params):
        self.param = TPDAParam()
        self.current_param = None
        self._params = params
        self._validate()

    def _validate(self):
        for (name, val,) in self._params:
            self._add(name, val)
            if name == 'signature':
                break

    def _add(self, name, value):
        if not self.current_param:
            self.current_param = self.param

        self.current_param = self.current_param.wants(name)
        if self.current_param:
            self.current_param.add(name, value.lower())
        else:
            print('weird {}={}'.format(name, value))

    def params(self):
        return self.param.as_dict()


def params(arg):
    """
    Parse `arg` and returns a dict describing the TPDA
    arguments.

    Resolution order:
        - `arg` is a string is parsed as an URL
        - `arg` has an items() method and is parsed
           (works for multidicts, ..)
        - `arg` is a iterable is parsed as a
           ((name, value), (name, value), ..)
    """
    if isinstance(arg, str):
        pr = parse.urlparse(arg)
        if not pr.query:
            raise exceptions.IncompleteURI
        return Params(parse.parse_qsl(pr.query)).params()
    elif hasattr(arg, 'items'):
        return Params(arg.items()).params()
    elif hasattr(arg, '__iter__'):
        return Params(arg).params()


def trusted_params(uri):
    """Walk through an URI, lookup the set of DNSKEYs for the origin
    third party provider domain, validate URI signature against the
    found keys. If valid, returns the trustable URI - otherwise raise
    an exception.

    /!\ User MUST use the returned URI, as signature validation is
    only done on everything *before* the URI.
    """
    # Truncate the signature= part
    try:
        uri, sig = uri.split('&signature=')
        sig = parse.unquote(sig)
    except ValueError:
        raise exceptions.IncompleteURI

    pr = parse.urlparse(uri)
    if not pr.query:
        raise exceptions.IncompleteURI

    expires = _qsl_get_one(pr.query, 'expires')
    if (datetime.datetime.utcnow() >
        datetime.datetime.strptime(expires, '%Y%m%d%H%M%S')):
        raise exceptions.Expired

    source = _qsl_get_one(pr.query, 'source')

    txtl = Checker(source, dnssec=True).txt('_tpda')
    if not txtl:
        raise exceptions.NoTPDA

    keys = [RSA.importKey(base64.b64decode(txt.encode('ascii')))
            for txt in txtl.split('\n')]

    digest = SHA256.new()
    digest.update(uri.encode('ascii'))

    for key in keys:
        signer = PKCS1_v1_5.new(key)
        if signer.verify(digest, base64.b64decode(sig)):
            return params(uri)

    raise exceptions.NoSignatureMatch
