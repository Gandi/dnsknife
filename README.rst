
dnsknife: a DNS tool
====================

Quick overview:
---------------

.. code:: python

    >>> import dnsknife
    >>> ans = dnsknife.query('example.com', 'A', dnssec=True)
Specific queries shortcuts:

.. code:: python

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



It can be used for DNSSEC lookups, implements a few CDS/CDNSKEY drafts:
-----------------------------------------------------------------------

.. code:: python

    >>> c = Checker('example.com')
    >>> with dnsknife.dnssec(c) as sec:
    >>>     print sec.spf()
    None

    >>> Checker('ten.pm').cdnskey()

    ---------------------------------------------------------------------------
    BadCDNSKEY                                Traceback (most recent call last)
    ...

    BadCDNSKEY: 1324 did not sign DNSKEY RR


It also has a few more functions for DNSSEC checks:
---------------------------------------------------

.. code:: python

    >>> keys = dnsknife.query('example.com', 'DNSKEY')
    >>> dnsknife.signed_by(ans, keys[0])
    True

.. code:: python

    >>> dnsknife.signers(dnsknife.Checker('pm.', dnssec=True).query('pm.', 'DNSKEY'))
    {<DNS name pm.>: [35968, 60859]}

.. code:: python

    >>> dnsknife.trusted(ans)
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

