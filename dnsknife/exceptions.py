from dns.resolver import NoAnswer  # noqa
from dns.exception import Timeout  # noqa


class BadAnswer(Exception):
    """On low level errors"""
    pass


class NoDNSSEC(Exception):
    """Whenever the recursive NS we use does not perform DNSSEC
    validation for our lookup, which might be for many reasons"""


class BadSignerName(Exception):
    pass


class DeleteDS(Exception):
    """Be explicit about CDNSKEY alg 0 when we have one."""


class BadCDNSKEY(Exception):
    pass


class NsLookupError(Exception):
    pass


class BadRcode(Exception):
    pass


# TPDA
class IncompleteURI(Exception):
    pass


class InvalidArgument(Exception):
    pass


class NoTPDA(Exception):
    """Whenever we're unable to lookup the DNSKEYs"""


class NoSignatureMatch(Exception):
    """No key matched the given signature"""


class DomainNotFound(Exception):
    pass


class TPDANotEnabled(Exception):
    pass


class ServiceNotPresent(Exception):
    pass


class UnsafeRedirect(Exception):
    pass
