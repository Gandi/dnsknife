import dns
from . import exceptions


def rrset_rrsig(response):
    """Split and return rrsig and rrset from answer"""
    try:
        rrsig = response.find_rrset(response.answer, response.question[0].name,
                                    dns.rdataclass.IN, dns.rdatatype.RRSIG,
                                    response.question[0].rdtype)
        rrset = response.find_rrset(response.answer, response.question[0].name,
                                    dns.rdataclass.IN,
                                    response.question[0].rdtype)

        return rrset, rrsig
    except KeyError:
        return [], []


def signers(answer):
    """Takes a dns.resolver.Answer, and return signer
    names and key_tags. Check that signers are allowed
    to sign names.

        {'signer': [keytag, keytag], ..}

    """
    rrset, rrsig = rrset_rrsig(answer.response)
    qname = answer.response.question[0].name

    signer_names = set(sig.signer for sig in rrsig)
    if not all([qname.is_subdomain(sn) for sn in signer_names]):
        raise exceptions.BadSignerName

    ret = {}
    for sig in rrsig:
        ret.setdefault(sig.signer, []).append(sig.key_tag)

    return ret


def signed_by(answer, dnskey):
    """Checks that a given dns.resolver.Answer has been signed
    by the given dns Key object."""
    rrset, rrsig = rrset_rrsig(answer.response)

    for sig in rrsig:
        if sig.key_tag == dns.dnssec.key_id(dnskey):
            try:
                dns.dnssec.validate_rrsig(rrset, sig, {sig.signer: [dnskey]})
                return True
            except:
                pass
    return False


def trusted(answer):
    """Check if one signer in the dns.resolver.Answer is trusted"""
    from .resolver import query
    for signer in signers(answer).keys():
        keyans = query(signer, dns.rdatatype.DNSKEY, True)
        for key in keyans:
            if signed_by(answer, key):
                return True
    return False
