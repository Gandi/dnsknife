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
        return socket.AF_INET


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


def ns_for(domain, dnssec=False):
    answer = query(domain, dns.rdatatype.NS, dnssec,
                    raise_on_no_answer=False)

    # If we have authority referral, use it
    if (answer.response.rcode() == dns.rcode.NOERROR
        and not answer.rrset):
        return ns_for(answer.response.authority[0].name, dnssec)

    return [ns.target.to_text() for ns in answer.rrset]


def ns_addrs_for(domain, dnssec=False):
    ns_list = ns_for(domain, dnssec)

    addrs = sum((ns_addr_insecure(ns) for ns in ns_list), [])

    if not can_ipv6:
        addrs = filter(lambda addr:
                       ip_family(addr) == socket.AF_INET, addrs)

    return addrs


def query(name, rdtype, dnssec=False, raise_on_no_answer=True):
    """Lookup. Using the locally configured resolvers
    by default. Eventually using the local NS AD bit as a trust source."""
    # Query for our name, let NXDOMAIN raise
    res = system_resolver
    res.use_edns(0, dns.flags.DO, edns0_size)

    # Convenience for external callers
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)

    answer = res.query(name, rdtype, raise_on_no_answer=raise_on_no_answer)

    # Double check we have DNSSEC validation
    if dnssec:
        if not answer.response.flags & dns.flags.AD:
            raise exceptions.NoDNSSEC('No AD flag from resolver')

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

    def query_at(self, qname, rdtype, addr, dnssec=False):
        rdclass = dns.rdataclass.IN
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        if isinstance(qname, str):
            qname = dns.name.from_text(qname)
        if isinstance(addr, str):
            if ip_family(addr):
                addr = (addr, 53,)
            else:
                addr = (ns_addr_insecure(addr)[0], 53)

        req = dns.message.make_query(qname, rdtype, rdclass)
        req.use_edns(0, dns.flags.DO, edns0_size)

        return FutureAnswer(self, req, addr, self.timeout, self.source,
                            self.source_port, dnssec)

    def query(self, qname, rdtype, dnssec=False):
        ns = system_resolver.nameservers
        if not len(ns):
            raise exceptions.NsLookupError('no nameservers')
        return self.query_at(qname, rdtype, random.sample(ns, 1)[0], dnssec)

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

        for fd, future in self.futures.items():
            if future.ready():
                self.unregister(fd)

    def poll_loop(self):
        while self.futures:
            self.one_poll_loop()

    def __enter__(self):
        return self

    def __exit__(self, exc, exc_val, exc_tb):
        self.poll_loop()
