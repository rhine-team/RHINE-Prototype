package main

import (
	"clientlib/rhine"
	"fmt"
	"github.com/miekg/dns"
	"strings"
)

const (
	DNSrhineCertPrefix = "_rhinecert."
	Resolver           = "localhost"
)

type Assertion struct {
	atype     string
	answer    string
	signature string
}

func main() {

	query := "host1.rhine-ns.com."

	m := new(dns.Msg)
	m.SetQuestion(query, dns.TypeTXT)

	c := new(dns.Client)
	assertion, _, err := c.Exchange(m, Resolver+":100")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(assertion.Answer)

	txt, _ := rhine.QueryRCertDNS(strings.SplitN(query, ".", 2)[1], Resolver, "100")

	fmt.Println(txt.Txt)

	_, _, pkey := rhine.ParseVerifyRhineCertTxtEntry(txt)

	fmt.Println(pkey)

	//assertiontxt, _ := assertion.Answer[0].(*dns.TXT)

	//ok := rhine.VerifyAssertions(pkey, []*dns.TXT{assertiontxt})
	//fmt.Println(ok)

}
