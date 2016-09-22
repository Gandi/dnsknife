"""
POC for a stateless challenge/response TXT domain ownership validation.
"""

import hmac
import time


def valid_tokens(domain, secret, validity=86400):
    def token_at(when):
        h = hmac.HMAC(secret)
        h.update(domain + str(round(when/validity)))
        return h.hexdigest()

    # We're not totally strict on validity, but want
    # to avoid the worst case where we provided a token
    # that immediately expires. Allow up to three half-validity
    # intervals in the past.

    now = int(time.time())
    validity = int(validity/2)
    past = now - 3*validity

    return [token_at(when) for when in xrange(past, now, validity)]
