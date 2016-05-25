import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.DNSKEY

dns.rdatatype.CDNSKEY = 60
dns.rdatatype._by_text['CDNSKEY'] = dns.rdatatype.CDNSKEY
dns.rdatatype._by_value[60] = 'CDNSKEY'

dns.rdata._rdata_modules[(dns.rdataclass.IN,
                          dns.rdatatype.CDNSKEY)] = dns.rdtypes.ANY.DNSKEY
dns.rdtypes.ANY.DNSKEY.CDNSKEY = dns.rdtypes.ANY.DNSKEY.DNSKEY

if not hasattr(dns.rdatatype, 'URI'):
    dns.rdatatype.URI = 256
    dns.rdatatype._by_text['URI'] = dns.rdatatype.URI

# For pickle/unpickle

del dns.name.Name.__setattr__
