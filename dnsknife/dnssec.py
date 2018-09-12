import dns
from dns.dnssec import key_id
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

    errs = []

    rrset, rrsig = rrset_rrsig(answer.response)

    for sig in rrsig:
        if sig.key_tag == key_id(dnskey):
            try:
                dns.dnssec.validate_rrsig(rrset, sig, {sig.signer: [dnskey]})
                return True, None
            except Exception as e:
                errs.append(str(e))
                pass
    return (False, errs)


def trusted(answer, raise_on_errors=False):
    """Check if one signer in the dns.resolver.Answer is trusted"""
    from .resolver import query
    errs = {}
    for signer in signers(answer).keys():
        keyans = query(signer, dns.rdatatype.DNSKEY, True)
        for key in keyans:
            sig, key_errs = signed_by(answer, key)
            if sig:
                return True
            errs[key_id(key)] = key_errs

    if raise_on_errors:
        raise exceptions.NoTrust(errs)

    return False


def matching_key(dnskeys, ds):
    """Return the key from dnskeys matching this DS"""
    dtype = {
        1: 'SHA1',
        2: 'SHA256',
        4: 'SHA384',
    }.get(ds.digest_type, 'SHA256')
    for k in dnskeys:
        candidate = dns.dnssec.make_ds(dnskeys.name, k, dtype)
        if candidate.digest == ds.digest:
            # Special case for CDS alg 0
            k.algorithm = ds.algorithm
            return k
