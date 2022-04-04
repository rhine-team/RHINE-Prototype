package rhine

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strings"
)

const (
	DNSrhineCertPrefix = "_rhinecert."
	txtrhinecertpredix = "rhineCert Ed25519"
	txtsigvalueprefix  = "rhineSig "
)

func VerifyAssertions(pkey ed25519.PublicKey, assertions []*dns.TXT) bool {
	for _, assertion := range assertions {
		if ok := VerifyAssertion(pkey, assertion); !ok {
			return false
		}
	}
	return true
}

func VerifyAssertion(pkey ed25519.PublicKey, txt *dns.TXT) bool {
	a := txt.Txt[0]
	message := strings.Split(a, " ")[0]
	//message = strings.ReplaceAll(message, " ", "")
	sigparts := strings.Split(a, " ")[1:]
	sigbase64 := strings.Join(sigparts, " ")
	//sigbase64 = strings.ReplaceAll(sigbase64, " ", "")
	sig, _ := base64.StdEncoding.DecodeString(sigbase64)
	ok := ed25519.Verify(pkey, []byte(message), sig)
	if !ok {
		return false
	}
	return true
}

func QueryRCertDNS(apex string, resolver string, port string) (*dns.TXT, *dns.Msg) {
	fmt.Println(apex)
	m := new(dns.Msg)
	m.SetQuestion(DNSrhineCertPrefix+apex, dns.TypeTXT)

	c := new(dns.Client)
	certtxt, _, err := c.Exchange(m, resolver+":"+port)
	if err != nil {
		log.Fatal(err)
	}

	txt, ok := certtxt.Answer[0].(*dns.TXT)

	if ok {
		return txt, certtxt
	} else {
		return nil, nil
	}

}

func ParseVerifyRhineCertTxtEntry(txt *dns.TXT) (error, *x509.Certificate, ed25519.PublicKey) {
	//TODO support other key types
	entries := txt.Txt
	entry := strings.Join(entries, " ")
	certstringchunks := strings.SplitAfter(entry, txtrhinecertpredix)[1:]
	encodedcert := strings.Join(certstringchunks, "")
	encodedcert = strings.ReplaceAll(encodedcert, " ", "")

	name := txt.Header().Name
	apexname := strings.SplitAfter(name, DNSrhineCertPrefix)[1]

	certdecoded, _ := base64.StdEncoding.DecodeString(encodedcert)

	cert, err := x509.ParseCertificate(certdecoded)
	if err != nil {
		fmt.Println("Parsing Rhine Cert failed! ", err)
		return err, nil, nil
	}

	var CaCertPool *x509.CertPool
	CaCertPool, _ = x509.SystemCertPool()

	CaCertPool.AppendCertsFromPEM([]byte("-----BEGIN CERTIFICATE-----\nMIIBJjCB2aADAgECAgEBMAUGAytlcDAbMRkwFwYDVQQDExBSSElORSBFWEFNUExF\nIENBMB4XDTIyMDIyMTA5MDI1NVoXDTIzMDIxMjA5MDI1NVowGzEZMBcGA1UEAxMQ\nUkhJTkUgRVhBTVBMRSBDQTAqMAUGAytlcAMhAFq9YoSG/zv2npflvTwmog9Ymijs\nK0NDTDYFgTbGxyrto0IwQDAOBgNVHQ8BAf8EBAMCAoQwDwYDVR0TAQH/BAUwAwEB\n/zAdBgNVHQ4EFgQUXcJH29E2egUuSdhJFoy/kJQDlcwwBQYDK2VwA0EAxB2JHVh+\nN7o3RTBCp7wOWDlGePd0xuhRhU4GEJs4CTxGgLbcyX1iIzF7kJ1qCmp+y180PAJe\nxqM22eY3hKQFAQ==\n-----END CERTIFICATE-----"))

	if _, err := cert.Verify(x509.VerifyOptions{
		DNSName: apexname,
		Roots:   CaCertPool,
	}); err != nil {
		fmt.Println("Rhine Cert Verification Failed!", err)
		return err, nil, nil
	}

	return nil, cert, cert.PublicKey.(ed25519.PublicKey)

}

func GroupRhineServerResp(resp dns.Msg) ([]dns.RR, *dns.TXT, *dns.TXT) {

	qtype := resp.Question[0].Qtype
	qname := resp.Question[0].Name

	answerRRs := []dns.RR{}
	var sigRR *dns.TXT
	var certRR *dns.TXT

	for _, rr := range resp.Answer {

		if rr.Header().Rrtype == dns.TypeTXT {
			rrtxt, _ := rr.(*dns.TXT)
			if strings.HasPrefix(rr.Header().Name, DNSrhineCertPrefix) && strings.HasPrefix(rrtxt.Txt[0], txtrhinecertpredix) {
				certRR, _ = rr.(*dns.TXT)
			} else if qname == rr.Header().Name && strings.HasPrefix(rrtxt.Txt[0], txtsigvalueprefix+dns.TypeToString[uint16(qtype)]) {
				sigRR, _ = rr.(*dns.TXT)
			}
		}

		if rr.Header().Rrtype == qtype {
			answerRRs = append(answerRRs, rr)
		}
	}

	return answerRRs, sigRR, certRR
}

func VerifySig(pkey ed25519.PublicKey, rrs []dns.RR, sig *dns.TXT) bool {
	messagestring := ""
	for _, rr := range rrs {
		messagestring += rr.String()
	}
	message := []byte(messagestring)

	entries := sig.Txt
	entry := strings.Join(entries, " ")
	sigstringchunks := strings.SplitAfter(entry, txtsigvalueprefix+dns.TypeToString[(rrs[0].Header().Rrtype)])[1:]
	encodedsig := strings.Join(sigstringchunks, "")
	encodedsig = strings.ReplaceAll(encodedsig, " ", "")

	sigdecoded, _ := base64.StdEncoding.DecodeString(encodedsig)

	return ed25519.Verify(pkey, message, sigdecoded)

}
