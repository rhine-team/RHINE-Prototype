package rhinesigner

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
)

const certprefix = "_rhinecert."
const txtsigprefix = ""
const txtsigvalueprefix = "rhineSig "
const txtcertvalueprefix = "rhineCert Ed25519 "
var RRStoSign = map[uint16]bool {
	dns.TypeA: true,
}

type Zone struct {
	Origin string
	Rrs map[dns.Type][]dns.RR
}

func (z Zone) Sign(cert *x509.Certificate, key ed25519.PrivateKey, origin string)  {

	certRR := createCertRR(cert, origin)
	
	signedTXTRRs := []dns.RR{}
	for rrSetsType, rrSets := range z.Rrs {
		signedTXTRRs = append(signedTXTRRs, signRRSets(rrSets, rrSetsType, key)...)
	}


	z.Rrs[dns.Type(dns.TypeTXT)] = append(z.Rrs[dns.Type(dns.TypeTXT)], certRR)
	z.Rrs[dns.Type(dns.TypeTXT)] = append(z.Rrs[dns.Type(dns.TypeTXT)], signedTXTRRs...)

	return
}


func createCertRR(cert *x509.Certificate, origin string) (dns.RR) {
	certRR := dns.TXT{}

	certRR.Hdr = dns.RR_Header{
		Name:     certprefix + origin,
		Rrtype:   dns.TypeTXT,
		Class:    dns.ClassINET,
		Ttl:      604800,
	}

	txtvalue := base64.StdEncoding.EncodeToString(cert.Raw)
	certRR.Txt = split255TXT(txtcertvalueprefix + txtvalue)

	return &certRR


}

func signRRSets(rrs []dns.RR, dnstype dns.Type, key ed25519.PrivateKey) ([]dns.RR){

	namemap := make(map[string][]dns.RR)
	signatureRRs := []dns.RR{}

	for _, rr := range rrs {
		if !RRStoSign[rr.Header().Rrtype] {
			continue
		}
		namemap[rr.Header().Name] = append(namemap[rr.Header().Name], rr)
	}


	for name, RRSet := range namemap {
		signedTXTRR := dns.TXT{}
		signedTXTRR.Hdr = dns.RR_Header{
			Name:     txtsigprefix + name,
			Rrtype:   dns.TypeTXT,
			Class: dns.ClassINET,
			Ttl: 604800,
		}

		messagestring := ""
		for _, rr := range RRSet {
			messagestring += rr.String()
		}

		message:= []byte(messagestring)
		sigdata:= ed25519.Sign(key, message)

		signedtxtvalue := txtsigvalueprefix + dns.TypeToString[uint16(dnstype)] + " " + base64.StdEncoding.EncodeToString(sigdata)
		signedTXTRR.Txt = split255TXT(signedtxtvalue)

		signatureRRs = append(signatureRRs, &signedTXTRR)
	}

	
	return signatureRRs
}


func (z Zone) Print() {
	for _, rrs := range z.Rrs {
		for _, rr := range rrs {
			fmt.Println(rr.String())
		}
	}
	return
}


func split255TXT (in string) []string {
	tmp := in
	res := []string{}

	for (len(tmp) > 255) {
		res = append(res, tmp[:255])
		tmp = tmp[255:]

	}

	if len(tmp) > 0 {
		res = append(res, tmp)
	}
	return res
}