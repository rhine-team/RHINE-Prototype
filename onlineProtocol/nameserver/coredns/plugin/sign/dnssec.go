package sign

import (
	"crypto"
	"github.com/miekg/dns"
)

func (p Pair) signRRs(rrs []dns.RR, signerName string, ttl, incep, expir uint32) (*dns.RRSIG, error) {
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeRRSIG, Ttl: ttl},
		Algorithm:  p.Public.Algorithm,
		SignerName: signerName,
		KeyTag:     p.KeyTag,
		OrigTtl:    ttl,
		Inception:  incep,
		Expiration: expir,
	}

	e := rrsig.Sign(p.Private, rrs)
	return rrsig, e
}

func signZSK(dnskey dns.RR, signer crypto.Signer, signerName string, ttl, incep, expir uint32) (*dns.RRSIG, error) {
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Rrtype: dns.TypeRRSIG, Ttl: ttl},
		Algorithm:  dns.ED25519,
		SignerName: signerName,
		KeyTag:     9991,
		OrigTtl:    ttl,
		Inception:  incep,
		Expiration: expir,
	}

	e := rrsig.Sign(signer, []dns.RR{dnskey})
	return rrsig, e
}
