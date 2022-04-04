package rhine

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strings"
)

const (
	DNSrhineCertPrefix = "_rhinecert."
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

func QueryRCertDNS(apex string, resolver string) (*dns.TXT, *dns.Msg) {
	fmt.Println(apex)
	m := new(dns.Msg)
	m.SetQuestion(DNSrhineCertPrefix+apex, dns.TypeTXT)

	c := new(dns.Client)
	certtxt, _, err := c.Exchange(m, resolver+":53")
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
	entry = strings.ReplaceAll(entry, " ", "")
	name := txt.Header().Name
	apexname := strings.SplitAfter(name, DNSrhineCertPrefix)[1]
	if !strings.HasPrefix(entry, "rhine_cert=") {
		return errors.New("Wrong attribute"), nil, nil
	}

	certstring := strings.SplitAfter(entry, "rhine_cert=")[1]

	certdecoded, _ := base64.StdEncoding.DecodeString(certstring)

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
