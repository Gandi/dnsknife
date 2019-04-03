from dns.resolver import NoAnswer  # noqa
from dns.exception import Timeout  # noqa


class Error(Exception):
    """Most problems raised from this module"""
    pass


class BadAnswer(Error):
    """On low level errors"""
    pass


class NoDNSSEC(Error):
    """Whenever the recursive NS we use does not perform DNSSEC
    validation for our lookup, which might be for many reasons"""


class NoTrust(Error):
    """Whenever trusted() fails"""


class BadSignerName(Error):
    pass


class DeleteDS(Error):
    """Be explicit about CDNSKEY alg 0 when we have one."""


class BadCDNSKEY(Error):
    pass


class NSDisagree(Error):
    """NServers do not have the same info"""


class LookupError(Error):
    pass


class NsLookupError(Error):
    pass


class BadRcode(Error):
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

class Expired(Exception):
    pass
