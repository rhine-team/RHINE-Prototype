package common

import (
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"github.com/miekg/dns"
)

func QueryDNSKeyRSA(zone string) (*rsa.PublicKey, error) {
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.SetQuestion(zone, dns.TypeDNSKEY)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	for _, rr := range in.Answer {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		// 257 = Key Signing Key , 256 = Zone Signing Key
		if !(dnskey.Flags == 257){
			continue
		}
		if !(dnskey.Algorithm == dns.RSASHA1 || dnskey.Algorithm == dns.RSASHA256 || dnskey.Algorithm == dns.RSASHA512 ){
			continue
		}

		return dnskey.PublicKeyRSA(), nil
	}
	return nil, errors.New("DNSKEY: Key not found")
}

func QueryDNSKeyEd25519(zone string) (ed25519.PublicKey, error) {
	m := new(dns.Msg)
	m.SetEdns0(4096, true)
	m.SetQuestion(zone, dns.TypeDNSKEY)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	for _, rr := range in.Answer {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		if !(dnskey.Flags == 257){
			continue
		}
		if !(dnskey.Algorithm == dns.ED25519 ){
			continue
		}

		return dnskey.PublicKeyED25519(), nil
	}
	return nil, errors.New("DNSKEY: Key not found")
}

