"""
POC for a stateless challenge/response TXT domain ownership validation.
"""

import hashlib
import hmac
import time


def valid_tokens(domain, secret, validity=86400):
    if isinstance(secret, str):
        secret = secret.encode()

    if isinstance(domain, str):
        domain = domain.encode('idna')

    def token_at(when):
        h = hmac.HMAC(secret, digestmod=hashlib.sha256)
        h.update(domain)
        h.update(str(int(when/validity)).encode())
        return h.hexdigest()

    # We're not totally strict on validity, but want
    # to avoid the worst case where we provided a token
    # that immediately expires. Allow up to three half-validity
    # intervals in the past.

    now = int(time.time())
    validity = int(validity/2)
    past = now - 3*validity

    return [token_at(when) for when in range(past, now, validity)]
