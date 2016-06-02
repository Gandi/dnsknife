# implements a few zone scanners..
import random

import dns

from . import exceptions
from . import resolver

NAMES = ['@', 'www', 'forum', 'secure', 'mail',
         'git', 'corp', 'localhost', 'autodiscover',
         'test', 'admin', 'support', '_xmpp._tcp',
         '_sip._tcp']


class Scanner:
    types = ['DNAME', 'A', 'AAAA', 'NS', 'MX', 'LOC', 'SPF', 'TXT',
             'URI']

    def __init__(self, domain):
        self.domain = domain
        self.names = NAMES[:]
        self.ns = resolver.ns_for(domain)

    def check_name(self, name, rdtypes):
        answers = []
        with resolver.Resolver() as r:
            qname = dns.name.from_text(name, dns.name.from_text(self.domain))
            for rdtype in rdtypes:
                ns = random.sample(self.ns, 1)[0]
                ans = r.query_at(qname, rdtype, ns)
                answers.append(ans)
        return answers

    def scan(self):
        seen = []
        new = []

        def relname(name):
            dom = dns.name.from_text(self.domain)
            return name.relativize(dom).to_text()

        def refers_to(rrset):
            if rrset.rdtype in (dns.rdatatype.MX,):
                return [rr.exchange for rr in rrset]
            if rrset.rdtype in (dns.rdatatype.CNAME, dns.rdatatype.DNAME,
                                dns.rdatatype.SRV, dns.rdatatype.NS):
                return [rr.target for rr in rrset]
            return []

        def consider(rrset):
            seen.append(relname(rrset.name))
            for name in refers_to(rrset):
                dom = dns.name.from_text(self.domain)
                if name.is_subdomain(dom):
                    if relname(name) not in seen:
                        new.append(relname(name))

        def scan_names(names, types):
            answers = []
            for name in names:
                for answer in self.check_name(name, types):
                    answers.append(answer)

            for answer in answers:
                name = relname(answer.query.q.question[0].name)
                try:
                    rrset = answer.get().rrset
                    consider(rrset)
                    yield name, rrset
                except (exceptions.NoAnswer, exceptions.Timeout) as e:
                    pass
                except exceptions.BadRcode as e:
                    # Bad rcode (refused) for additional name
                    yield name, None

        # Wildcard ?
        for ans in self.check_name('*', ['CNAME']):
            try:
                ans.get()
            except exceptions.NoAnswer as e:
                self.names = ['@', '*']
            except (exceptions.BadRcode):
                pass

        # First, scan for valid names. Remove NXDOMAINS, keep NOANSWER
        # Lookup aliases first so we can consider the right name
        for name, rrset in scan_names(self.names, ['CNAME']):
            if rrset:
                yield rrset
            else:
                self.names.remove(name)

        # Second, in valid names - scan for all possible types
        for name, rrset in scan_names(self.names, self.types):
            if rrset:
                yield rrset

        # Extend with newly discovered names
        for name, rrset in scan_names(new, self.types):
            if rrset:
                yield rrset
