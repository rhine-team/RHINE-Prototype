package rhine

import (
	"github.com/miekg/dns"
	"strings"
)

func QueryNameRhine(name string, server string) string {

	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeTXT)

	c := new(dns.Client)
	assertion, _, err := c.Exchange(m, server+":53")
	if err != nil {
		return "Server @"+server+":53 not reachable\n" + err.Error()
	}

	if len(assertion.Answer) == 0 {
		return "Error: No TXT RR for " + name + " found\n" +  assertion.String()
	}

	assertiontxt, assertionOk := assertion.Answer[0].(*dns.TXT)
	if !assertionOk {
		return "Error: No TXT RR for " + name + " found\n" +  assertion.String()
	}

	txt, certanswer := QueryRCertDNS(strings.SplitN(name, ".", 2)[1], server)

	err, _, pkey := ParseVerifyRhineCertTxtEntry(txt)
	if err != nil {
		return "Error: Parse and Verify RCert failed: " + err.Error()
	}

	if VerifyAssertions(pkey, []*dns.TXT{assertiontxt}) {
		return PrintResponse(certanswer, assertion, true)
	}

	return PrintResponse(certanswer, assertion, false)
}

func QueryNameDNSSEC(name string, server string) string {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.SetEdns0(4096, true)

	c := new(dns.Client)
	ans, _, err := c.Exchange(m, server+":53")
	if err != nil {
		return "Server @"+server+":53 not reachable\n" + err.Error()
	}

	if len(ans.Answer) == 0 {
		return "Error: No TXT RR for " + name + " found\n" +  ans.String()
	}

	_, isA := ans.Answer[0].(*dns.A)
	if !isA {
		return "Error: No TXT RR for " + name + " found\n" +  ans.String()
	}

	return ans.String()
}

func QueryNameDNS(name string, server string) string {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)

	c := new(dns.Client)
	ans, _, err := c.Exchange(m, server+":53")
	if err != nil {
		return "Server @"+server+":53 not reachable\n" + err.Error()
	}

	if len(ans.Answer) == 0 {
		return "Error: No TXT RR for " + name + " found\n" +  ans.String()
	}

	_, isA := ans.Answer[0].(*dns.A)
	if !isA {
		return "Error: No TXT RR for " + name + " found\n" +  ans.String()
	}

	return ans.String()

}



func PrintResponse(msgCert *dns.Msg, msgName *dns.Msg, verified bool) string {
	var res string
	res = msgCert.String()
	res += "\n"
	res += msgName.String()
	res += "\n"

	if verified {
		res += "=======================================================================\n"
		res += " Verified " + msgName.Answer[0].Header().Name + " with " + msgCert.Answer[0].Header().Name
	} else {
		res += "=======================================================================\n"
		res += " Failed to Verify " + msgName.Answer[0].Header().Name + " with " + msgCert.Answer[0].Header().Name
	}


	return res

}