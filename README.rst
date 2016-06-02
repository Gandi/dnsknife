
dnsknife: a DNS tool
====================

Quick overview:
---------------

.. code:: python

    >>> from dnsknife import resolver
    >>> ans = resolver.query('example.com', 'A', dnssec=True)

Specific queries shortcuts:

.. code:: python

    >>> import dnsknife
    >>> print dnsknife.Checker('example.com').mx()
    []

    >>> print dnsknife.Checker('example.com').spf()
    None

    >>> print dnsknife.Checker('example.com').txt()
    $Id: example.com 4415 2015-08-24 20:12:23Z davids $
    v=spf1 -all


Checking a domain TXT record is installed, looking at each domain NS (no
local caches) for a match:

.. code:: python

    >>> from dnsknife import Checker
    >>> Checker('example.com', direct=True).has_txt('dbef8938bef', ['www'], ignore_case=True)
    False

Querying a few dozen things at the same time:

.. code:: python

    >>> from dnsknife.resolver import Resolver
    >>> with Resolver(timeout=2) as r:
            a = r.query_at('www.example.com', 'A', '1.2.3.4')
            ...
            x = r.query_at('www.example.com', 'A', '1.2.3.4')

    >>> print a.get()
    <dns.resolver.Answer at 0x7f6e3d398ad0>

    >>> print x.get()
    <dns.resolver.Answer at 0x7f6e3d398bd0>

Scanning a zone:

.. code:: python

    In [16]: from dnsknife.scanner import Scanner
    In [9]: time list(scanner.Scanner('google.com').scan())
    CPU times: user 476 ms, sys: 28 ms, total: 504 ms
    Wall time: 2.4 s
    Out[9]: 
    [<DNS mail.google.com. IN CNAME RRset>,
     <DNS support.google.com. IN CNAME RRset>,
     <DNS google.com. IN A RRset>,
     <DNS google.com. IN AAAA RRset>,
     <DNS google.com. IN NS RRset>,
     <DNS google.com. IN MX RRset>,
     <DNS google.com. IN TXT RRset>,
     <DNS www.google.com. IN A RRset>,
     <DNS www.google.com. IN AAAA RRset>,
     <DNS googlemail.l.google.com. IN A RRset>,
     <DNS googlemail.l.google.com. IN AAAA RRset>,
     <DNS mail.google.com. IN TXT RRset>,
     <DNS corp.google.com. IN A RRset>,
     <DNS corp.google.com. IN AAAA RRset>,
     <DNS corp.google.com. IN NS RRset>,
     <DNS admin.google.com. IN A RRset>,
     <DNS admin.google.com. IN AAAA RRset>,
     <DNS www3.l.google.com. IN A RRset>,
     <DNS www3.l.google.com. IN AAAA RRset>,
     <DNS googlemail.l.google.com. IN A RRset>,
     <DNS googlemail.l.google.com. IN AAAA RRset>,
     <DNS www3.l.google.com. IN A RRset>,
     <DNS www3.l.google.com. IN AAAA RRset>,
     <DNS ns4.google.com. IN A RRset>,
     <DNS ns2.google.com. IN A RRset>,
     <DNS ns1.google.com. IN A RRset>,
     <DNS ns3.google.com. IN A RRset>,
     <DNS alt4.aspmx.l.google.com. IN A RRset>,
     <DNS alt4.aspmx.l.google.com. IN AAAA RRset>,
     <DNS aspmx.l.google.com. IN A RRset>,
     <DNS aspmx.l.google.com. IN AAAA RRset>,
     <DNS alt2.aspmx.l.google.com. IN A RRset>,
     <DNS alt2.aspmx.l.google.com. IN AAAA RRset>,
     <DNS alt1.aspmx.l.google.com. IN A RRset>,
     <DNS alt1.aspmx.l.google.com. IN AAAA RRset>,
     <DNS alt3.aspmx.l.google.com. IN A RRset>,
     <DNS alt3.aspmx.l.google.com. IN AAAA RRset>,
     <DNS ns2.google.com. IN A RRset>,
     <DNS ns1.google.com. IN A RRset>,
     <DNS ns3.google.com. IN A RRset>,
     <DNS ns4.google.com. IN A RRset>]


It can be used for DNSSEC lookups, implements a few CDS/CDNSKEY drafts:
-----------------------------------------------------------------------

.. code:: python

    >>> c = Checker('example.com', dnssec=True)
    >>> print c.spf()
    None

    >>> Checker('ten.pm').cdnskey()

    ---------------------------------------------------------------------------
    BadCDNSKEY                                Traceback (most recent call last)
    ...

    BadCDNSKEY: 1324 did not sign DNSKEY RR

.. code:: python

    >>> from dnsknife import dnssec, resolver
    >>> keys = resolver.query('example.com', 'DNSKEY')
    >>> dnssec.signed_by(ans, keys[0])
    True

.. code:: python

    >>> dnssec.signers(dnsknife.Checker('pm.', dnssec=True)
                       .query_relative('', 'DNSKEY'))
    {<DNS name pm.>: [35968, 60859]}

.. code:: python

    >>> dnssec.trusted(ans)
    True


Finally it implements TPDA - the draft_ can be found in docs_.
----------------------------------------------------------------

.. _docs: docs/
.. _draft: docs/extending_registrar_functions.txt

A third party provider wanting to change customer NS:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    >>> from dnsknife import tpda

    >>> # initialize with private key from repo:
    >>> client = tpda.Client('ten.pm', 'dnsknife/tests/test.key')

    >>> # generate url for domain
    >>> URI = client.nameservers_uri('whe.re', ['ns1.ten.pm','ns2.ten.pm'])

A DNS operator/registrar validating inbound params:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    >>> tpda.validate_URI(URI)
    'http://partners.gandi.net/nameservers/v1?source=ten.pm&domain=whe.re&expires=20160415000918&ns=ns1.ten.pm&ns=ns2.ten.pm'

