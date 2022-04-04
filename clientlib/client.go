package main

import (
	"fmt"
	"github.com/miekg/dns"
	"clientlib/rhine"
	"strings"
)

const (
	DNSrhineCertPrefix = "_rhinecert."
	Resolver = "172.17.0.2"
)

type Assertion struct {
	atype string
	answer string
	signature string
}


func main() {

	query := "host1.rhine-ns.com."

	m := new(dns.Msg)
	m.SetQuestion(query, dns.TypeTXT)

	c := new(dns.Client)
	assertion, _, err := c.Exchange(m, Resolver+":53")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(assertion.Answer)

	txt := rhine.QueryRCertDNS(strings.SplitN(query, ".", 2)[1], Resolver)

	_, _, pkey := rhine.ParseVerifyRhineCertTxtEntry(txt)

	fmt.Println(pkey)

	assertiontxt, _ := assertion.Answer[0].(*dns.TXT)


	ok := rhine.VerifyAssertions(pkey, []*dns.TXT{assertiontxt})
	fmt.Println(ok)


}

