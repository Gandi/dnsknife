from __future__ import absolute_import, print_function

from . import Checker

def lookup(email, dnssec=True):
    """Convenience"""
    local, domain = email.split('@', 2)
    return Checker(domain, dnssec=dnssec).openpgp(local)
