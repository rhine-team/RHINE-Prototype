package rhine

import (
	"fmt"
	"github.com/miekg/dns"
)

func QueryNameRhine(name string, server string, port string) string {
	println("in here")
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)

	c := new(dns.Client)
	resp, _, err := c.Exchange(m, server+":"+port)
	if err != nil {
		return "Server @" + server + ":" + port + " not reachable\n" + err.Error()
	}

	if len(resp.Answer) == 0 {
		return "Error: No Answer for " + name + " found\n" + resp.String()
	}
	for _, a := range resp.Answer {
		println(a.String())
	}
	fmt.Printf("%v", resp)
	answerRRs, sigRR, certRR := GroupRhineServerResp(*resp)
	println("grouped", answerRRs, sigRR, certRR)

	//if certRR == nil {
	//	certRR, certanswer := QueryRCertDNS(strings.SplitN(name, ".", 2)[1], server, port)
	//	fmt.Println("queried cert: ", certRR.String(), certanswer)
	//}

	err, _, pkey := ParseVerifyRhineCertTxtEntry(certRR)
	if err != nil {
		return "Error: Parse and Verify RCert failed: " + err.Error()
	}

	if VerifySig(pkey, answerRRs, sigRR) {
		return "verified"
	}

	return "failed"
}

func QueryNameDNSSEC(name string, server string, port string) string {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	m.SetEdns0(4096, true)

	c := new(dns.Client)
	ans, _, err := c.Exchange(m, server+":"+port)
	if err != nil {
		return "Server @" + server + ":" + port + " not reachable\n" + err.Error()
	}

	if len(ans.Answer) == 0 {
		return "Error: No TXT RR for " + name + " found\n" + ans.String()
	}

	_, isA := ans.Answer[0].(*dns.A)
	if !isA {
		return "Error: No TXT RR for " + name + " found\n" + ans.String()
	}

	return ans.String()
}

func QueryNameDNS(name string, server string, port string) string {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)

	c := new(dns.Client)
	ans, _, err := c.Exchange(m, server+":"+port)
	if err != nil {
		return "Server @" + server + ":" + port + " not reachable\n" + err.Error()
	}

	if len(ans.Answer) == 0 {
		return "Error: No TXT RR for " + name + " found\n" + ans.String()
	}

	_, isA := ans.Answer[0].(*dns.A)
	if !isA {
		return "Error: No TXT RR for " + name + " found\n" + ans.String()
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
