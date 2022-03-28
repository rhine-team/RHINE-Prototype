// domain related functions

package common

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"time"
)

func BytesToStrings(in []byte) []string {
	var out []string
	for i := range in {
		if i%255 == 0 {
			out = append(out, "")
		}
		//out[len(out)-1] += string(in[i])
		out[len(out)-1] += fmt.Sprintf("\\%d%d%d", in[i]/100%10, in[i]/10%10, in[i]%10)
	}

	return out
}

func StringsToBytes(in []string) []byte {
	var out []byte
	for _, s := range in {
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				if i == len(s) {
					break
				}
				// check for \DDD
				if i+2 < len(s) && isDigit(s[i]) && isDigit(s[i+1]) && isDigit(s[i+2]) {
					out = append(out, dddStringToByte(s[i:]))
					i += 2
				} else {
					out = append(out, byte(s[i]))
				}
			} else {
				out = append(out, byte(s[i]))
			}
		}
	}
	return out
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func dddToByte(s []byte) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

func dddStringToByte(s string) byte {
	_ = s[2] // bounds check hint to compiler; see golang.org/issue/14808
	return byte((s[0]-'0')*100 + (s[1]-'0')*10 + (s[2] - '0'))
}

// SetupEdns0Opt will retrieve the EDNS0 OPT or create it if it does not exist.
func SetupEdns0Opt(r *dns.Msg, length uint16) *dns.OPT {
	o := r.IsEdns0()
	if o == nil {
		r.SetEdns0(length, false)
		o = r.IsEdns0()
	}
	return o
}

func RetrieveTxtRecord(domain string, resolverAddress string, tcpOnly bool) ([]byte, error) {
	// query DNS proof entry
	var resp *dns.Msg
	var rtt time.Duration
	var err error

	if !tcpOnly {
		m := new(dns.Msg)
		m.SetQuestion(domain, dns.TypeTXT)
		SetupEdns0Opt(m, 4096)
		c := new(dns.Client)
		resp, rtt, err = c.Exchange(m, resolverAddress)
		if err != nil {
			return nil, fmt.Errorf("Failed to query map server: %s", err)
		}
	}
	if tcpOnly || resp.Truncated {
		if !tcpOnly {
			log.Print("DNS (UDP) response truncated; Retrying with TCP ...")
		}
		cTcp := dns.Client{Net: "tcp"}
		mTcp := new(dns.Msg)
		mTcp.SetQuestion(domain, dns.TypeTXT)
		SetupEdns0Opt(mTcp, 65507)
		resp, rtt, err = cTcp.Exchange(mTcp, resolverAddress)
		if err != nil {
			return nil, fmt.Errorf("Failed to query map server using TCP: %s", err)
		}
		if resp.Truncated {
			return nil, fmt.Errorf("DNS server returned a truncated DNS TCP reply")
		}
	}

	// extract bytes from txt records
	t0 := time.Now()
	var txtBytes []byte
	if txt, ok := resp.Answer[0].(*dns.TXT); !ok {
		return nil, fmt.Errorf("DNS reply does not contain TXT record")
	} else {
		txtBytes = StringsToBytes(txt.Txt)
	}
	t1 := time.Now()
	_ = rtt
	_ = t0
	_ = t1
	//log.Printf("rtt = %s, extraction = %s", rtt, t1.Sub(t0))
	return txtBytes, nil
}
