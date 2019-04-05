import errno
import random
import select
import socket
import struct
import time

import dns
try:
    import socks
    __socks_available = True
except ImportError:
    __socks_available = False

from . import exceptions
from . import dnssec

"""
with dnsknife.resolver.AsyncResolver() as r:
    future = r.query_at('www', 'A', somehost)

future.get()
"""

edns0_size = 4096
system_resolver = dns.resolver.Resolver()
# resolv.conf timeout option is not parsed yet, work around that
system_resolver.timeout = 1
system_resolver.cache = dns.resolver.Cache(5) # Cache expires fast
pysocks = None


def set_socks5_server(addr, port=1080, username=None, password=None):
    if not __socks_available:
        raise ImportError('No module named socks')

    socks.set_default_proxy(socks.SOCKS5, addr, port, False, username,
                            password)
    global pysocks
    pysocks = socks


def set_edns0_size(size):
    edns0_size = size


can_ipv6 = False
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
    s.connect(('2::', 53))
    can_ipv6 = True
except:
    pass


def set_nameservers(ns):
    system_resolver.nameservers = ns


def ip_family(addr):
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return socket.AF_INET6
    except:
        pass

    try:
        socket.inet_pton(socket.AF_INET, addr)
        return socket.AF_INET
    except:
        pass


def make_socket(proto, addr, source=None, source_port=0):
    af = ip_family(addr[0])

    if pysocks:
        sock = pysocks.socksocket(af, proto, 0)
    else:
        sock = socket.socket(af, proto, 0)

    sock.setblocking(0)

    if source is None:
        source = {socket.AF_INET: '0.0.0.0',
                  socket.AF_INET6: '::'}[af]
    try:
        sock.bind((source, source_port,))
        sock.connect(addr)
    except socket.error as e:
        if e.args == errno.EINPROGRESS:
            pass
    return sock

def maybe_pollute_cache_from_additional(answer):
    """
    This is ugly - In case we're looking at a borken NS
    it might have been collected from the roots by our cache.
    The process is:
    a/ Local cache gets NS+additional
    b/ NS is unreachable, cannot get an actual answer RRSET: timeout
       or servfail
    c/ We re-ask the local cache with norecurse: got the NS & Glue
    d/ We pollute the cache. So if we lookup that NS name, it will
       get resolved to this IP.

    This is only to help RFC1918 hosts to be able to lookup NS without
    direct access to root servers. We should find a better, cleaner way
    to locate NS when we have public IP or socks support.

    Okay this is so ugly I'm not even using it.
    """
    nsnames = (item.target for x in answer.response.authority if
        x.rdtype == dns.rdatatype.NS for item in x.items)
    for add in answer.response.additional:
        if add.name in nsnames:
            rrset = answer.response.find_rrset(answer.response.answer, add.name,
                    add.rdclass, add.rdtype, create=True)
            rrset.items += add.items
            cachedA = dns.resolver.Answer(add.name, add.rdtype, add.rdclass,
                    answer.response, False)
            system_resolver.cache.put((add.name, add.rdtype, add.rdclass),
                    cachedA)


def ns_for(domain, dnssec=False):
    if isinstance(domain, str):
        domain = dns.name.from_text(domain)

    try:
        answer = query(domain, dns.rdatatype.NS, dnssec,
                        raise_on_no_answer=False)
    # For broken NS, we'll get timeouts and SERVFAILs
    except dns.resolver.NoNameservers:
        # In that case, don't recurse and try to find something anyway
        answer = query(domain, dns.rdatatype.NS, dnssec,
                        raise_on_no_answer=False, recurse=False)
        for auth in answer.response.authority:
            if (domain.is_subdomain(auth.name) and
              auth.rdtype == dns.rdatatype.NS):
                return [r.target.to_text() for r in auth.items]
        return []

    # If we have authority referral up, use it
    if (answer.response.rcode() == dns.rcode.NOERROR
        and not answer.rrset):
        for auth in answer.response.authority:
            if domain != auth.name and domain.is_subdomain(auth.name):
                return ns_for(auth.name, dnssec)
    else:
        return [ns.target.to_text() for ns in answer.rrset]

    # If CNAME != question, try parent
    if answer.canonical_name != domain:
        return ns_for(domain.parent(), dnssec)


def addr_insecure(host, ipv6=True):
    """Insecure lookup of A - mostly used to discover nameservers,
    do not use for other purposes if security is a concern."""
    ans = []
    rdtypes = [dns.rdatatype.A]
    if ipv6:
        rdtypes.append(dns.rdatatype.AAAA)

    for rdtype in rdtypes:
        ret = query(host, rdtype, raise_on_no_answer=False)
        for rrset in ret.response.answer:
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                ans += [x.to_text() for x in rrset.items]

    if len(ans) == 0:
        raise exceptions.LookupError(host)
    return ans


def addresses(list_of_names):
    return sum((addr_insecure(x, can_ipv6) for x in list_of_names), [])


def query(name, rdtype, dnssec=False, raise_on_no_answer=True,
        recurse=True):
    """Lookup. Using the locally configured resolvers
    by default. Eventually using the local NS AD bit as a trust source."""
    # Query for our name, let NXDOMAIN raise
    res = system_resolver
    res.use_edns(0, dns.flags.DO, edns0_size)

    # Bad side effect here
    if not recurse:
        res.set_flags(0)
    else:
        res.set_flags(dns.flags.RD)

    # Convenience for external callers
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)

    answer = res.query(name, rdtype, raise_on_no_answer=raise_on_no_answer)

    # Double check we have DNSSEC validation
    if dnssec:
        if not answer.response.flags & dns.flags.AD:
            raise exceptions.NoDNSSEC('No AD flag from resolver')

    return answer


class Future:
    def __init__(self, timeout=0):
        if timeout:
            self.deadline = time.time() + timeout
        else:
            self.deadline = None
        self.timed_out = False

    def ready(self):
        if self.deadline and time.time() > self.deadline:
            self.timed_out = True
            return True

        if self._ready():
            fn = getattr(self, 'on_ready', None)
            if fn:
                fn()
                del self.on_ready
            return True
        return False

    def get(self):
        if self.timed_out:
            raise exceptions.Timeout
        return self._get()


class UDPQuery(Future):
    def __init__(self, q, where, source=None, source_port=0, timeout=2):
        Future.__init__(self, timeout)
        self.q = q
        self.rdmsg = b''
        self.net_args = (where, source, source_port)
        self.socket = self.make_socket(*self.net_args)
        self.answer = None
        self.wrmsg = q.to_wire()

    def make_socket(self, *args):
        return make_socket(socket.SOCK_DGRAM, *args)

    def get_sock(self):
        return self.socket

    def retry(self):
        self.socket = self.make_socket(*self.net_args)
        self.wrmsg = self.q.to_wire()

    def writable(self):
        if len(self.wrmsg):
            l = self.socket.send(self.wrmsg)
            self.wrmsg = self.wrmsg[l:]
        return len(self.wrmsg)

    def readable(self):
        buf = self.socket.recv(4096)
        self.rdmsg += buf
        if self.ready():
            return False
        return True

    def _ready(self):
        if len(self.rdmsg):
            try:
                dns.message.from_wire(self.rdmsg)
                return True
            except Exception as e:
                pass
        return False

    def _get(self):
        return dns.message.from_wire(self.rdmsg)


class TCPQuery(UDPQuery):
    def __init__(self, q, where, source, source_port, timeout=10):
        UDPQuery.__init__(self, q, where, source, source_port, timeout)
        self.wrmsg = struct.pack('!H', len(self.wrmsg)) + self.wrmsg
        self.headlen = 0

    def make_socket(self, *args):
        return make_socket(socket.SOCK_STREAM, *args)

    def _ready(self):
        if self.headlen:
            return True
        if len(self.rdmsg) >= 2:
            (l,) = struct.unpack("!H", self.rdmsg[:2])
            if len(self.rdmsg) == l + 2:
                self.headlen = l
                self.rdmsg = self.rdmsg[2:]
                return True
        return False


class FutureAnswer(Future):
    def __init__(self, context, req, where, timeout=0, source=None,
                 source_port=0, validate=False):
        Future.__init__(self, 0)
        self.context = context
        self.net_args = (where, source, source_port)

        self.req = req
        self.timeout = timeout
        self.attempts = 5

        self.query = UDPQuery(self.req, *self.net_args, timeout=timeout)
        self.query.on_ready = self.notify_ready
        self.context.register(self.query)

        self.validate = validate

    def notify_ready(self):
        try:
            q = self.query.get()
            if q.flags & dns.flags.TC:
                self.query = TCPQuery(self.req, *self.net_args,
                                      timeout=self.timeout)
                self.query.on_ready = self.notify_ready
                self.context.register(self.query)
        except exceptions.Timeout:
            self.attempts -= 1
            if self.attempts > 0:
                self.query.retry()
                self.context.register(self.query)
            else:
                raise

    def _ready(self):
        return self.query.ready()

    def _get(self):
        while not self.ready():
            self.context.one_poll_loop()

        ans = self.query.get()
        if ans.rcode() != dns.rcode.NOERROR:
            raise exceptions.BadRcode(dns.rcode.to_text(ans.rcode()))

        q = self.req
        if not q.is_response(ans):
            raise exceptions.BadAnswer

        answer = dns.resolver.Answer(q.question[0].name, q.question[0].rdtype,
                                     q.question[0].rdclass, ans)

        if self.validate:
            dnssec.trusted(answer, raise_on_errors=True)

        return answer


class Resolver:
    def __init__(self, timeout=0, source=None, source_port=0):
        self.futures = {}
        self.poll = select.poll()
        self.source_port = source_port
        self.source = source
        self.timeout = timeout

    def query_at(self, qname, rdtype, addr, dnssec=False, subnet=None,
                 prefixlen=None):
        """Query for a given name/type at given nameserver.
        qname: The query name (dns.name or string)
        rdtype: The query type (some dns.rdatatype or string)
        addr: The server address (tuple (addr,port), string hostname
                                  or string ip address)
        dnssec: Raise if no dnssec validation (bool)
        subnet: Client address for EDNS client subnet information (string)
        prefixlen: EDNS client subnet prefix length (int)
        """


        rdclass = dns.rdataclass.IN
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        if isinstance(qname, str):
            qname = dns.name.from_text(qname)
        if not isinstance(addr, tuple):
            if ip_family(addr):
                addr = (addr, 53,)
            else:
                addr = (addr_insecure(addr)[0], 53)

        req = dns.message.make_query(qname, rdtype, rdclass)
        opts = []
        if subnet:
            opts = [dns.edns.ECSOption(subnet, prefixlen)]
        req.use_edns(0, dns.flags.DO, edns0_size, options=opts)

        return FutureAnswer(self, req, addr, self.timeout, self.source,
                            self.source_port, dnssec)

    def query(self, qname, rdtype, dnssec=False, subnet=None, prefixlen=None):
        """Query for a given name/type.
        qname: The query name (dns.name or string)
        rdtype: The query type (some dns.rdatatype or string)
        dnssec: Raise if no dnssec validation (bool)
        subnet: Client address for EDNS client subnet information (string)
        prefixlen: EDNS client subnet prefix length (int)
        """

        ns = system_resolver.nameservers
        if not len(ns):
            raise exceptions.NsLookupError('no nameservers')
        return self.query_at(qname, rdtype, random.sample(ns, 1)[0], dnssec,
                             subnet, prefixlen)

    def register(self, future):
        sock = future.get_sock()
        self.poll.register(sock.fileno(), select.POLLIN | select.POLLOUT)
        self.futures[sock.fileno()] = future

    def unregister(self, fd):
        self.poll.unregister(fd)
        del self.futures[fd]

    def one_poll_loop(self):
        if self.futures:
            for (fd, ev) in self.poll.poll(1):
                future = self.futures[fd]
                if ev & select.POLLOUT:
                    if not future.writable():
                        self.poll.modify(fd, select.POLLIN)
                if ev & select.POLLIN:
                    if not future.readable():
                        self.unregister(fd)
                if ev & (select.POLLERR | select.POLLHUP):
                    self.unregister(fd)

        for fd, future in list(self.futures.items()):
            if future.ready():
                self.unregister(fd)

    def poll_loop(self):
        while self.futures:
            self.one_poll_loop()

    def __enter__(self):
        return self

    def __exit__(self, exc, exc_val, exc_tb):
        self.poll_loop()
