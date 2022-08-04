package resolver

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"hash/fnv"
	"os"
	"strings"
	"time"
)

const (
	// TODO for rootzone
	DNSrhineCertPrefix = "_rhinecert."
	DNSdspprefix       = "_dsp."
	txtrhinecertprefix = "rhineCert Ed25519"

	_RO               = 1 << 14 // RHINE OK
	defaultUDPBufSize = 2048
)

type ROA struct {
	rcert  *dns.TXT
	dsp    *dns.TXT
	dnskey *dns.DNSKEY
	keySig *dns.RRSIG
}

// Ro returns the value of the DO (DNSSEC OK) bit.
func Ro(rr *dns.OPT) bool {
	return rr.Hdr.Ttl&_RO == _RO
}

// SetRoOpt sets the RO (RHINE OK) bit.
// If we pass an argument, set the DO bit to that value.
// It is possible to pass 2 or more arguments. Any arguments after the 1st is silently ignored.
func SetRoOpt(rr *dns.OPT, ro ...bool) {
	if len(ro) == 1 {
		if ro[0] {
			rr.Hdr.Ttl |= _RO
		} else {
			rr.Hdr.Ttl &^= _RO
		}
	} else {
		rr.Hdr.Ttl |= _RO
	}
}

func setRo(m *dns.Msg) {
	o := m.IsEdns0()
	if o != nil {
		SetRoOpt(o)
		o.SetUDPSize(defaultUDPBufSize)
		return
	}

	o = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	SetRoOpt(o)
	o.SetUDPSize(defaultUDPBufSize)
	m.Extra = append(m.Extra, o)
}

func isDelegated(dsp *dns.TXT, origin string, qname string) bool {
	if dsp == nil {
		return false
	}
	delegs := strings.Join(dsp.Txt, " ")
	for _, deleg := range strings.Split(delegs, " ") {
		zone := deleg + "." + origin
		// If there is delegation for closer parent of the queried domain but not cached,
		// we have to query the dnskey/rcert for it.
		if dns.IsSubDomain(zone, qname) {
			return true
		}
	}
	return false
}

func verifyRhineROA(roa *ROA, certFile string) bool {
	_, publiKey, err := ParseVerifyRhineCertTxtEntry(roa.rcert, certFile)
	if err != nil {
		log.Warn(err.Error())
		return false
	}
	log.Debug("RCert successfully parsed")
	// TODO add more key type
	sig := roa.keySig
	key := roa.dnskey
	var expired string
	if !sig.ValidityPeriod(time.Now().UTC()) {
		expired = "(*EXPIRED*)"
	}
	if err := sig.VerifyWithPublicKey(publiKey, []dns.RR{key}); err != nil {
		log.Warn("[RHINE] ;- Bogus signature, %s does not validate (RCert) [%s] %s\n",
			shortSig(sig), err.Error(), expired)
		return false
	}

	return true
}

func ParseVerifyRhineCertTxtEntry(txt *dns.TXT, certFile string) (*x509.Certificate, ed25519.PublicKey, error) {
	//TODO support other key types
	entries := txt.Txt
	entry := strings.Join(entries, " ")
	certstringchunks := strings.SplitAfter(entry, txtrhinecertprefix)[1:]
	encodedcert := strings.Join(certstringchunks, "")
	encodedcert = strings.ReplaceAll(encodedcert, " ", "")

	certdecoded, _ := base64.StdEncoding.DecodeString(encodedcert)

	cert, err := x509.ParseCertificate(certdecoded)
	if err != nil {
		log.Warn("Parsing Rhine Cert failed! ", err)
		return nil, nil, err
	}

	// TODO(lou): Enable Cert verification later
	name := txt.Header().Name
	apexname := strings.SplitAfter(name, DNSrhineCertPrefix)[1]
	var CaCertPool *x509.CertPool
	CaCertPool, _ = x509.SystemCertPool()

	CaCert, err := os.ReadFile(certFile)
	CaCertPool.AppendCertsFromPEM(CaCert)

	if _, err := cert.Verify(x509.VerifyOptions{
		DNSName: apexname,
		Roots:   CaCertPool,
	}); err != nil {
		log.Warn("Rhine Cert Verification Failed!", err)
		return nil, nil, err
	}

	return cert, cert.PublicKey.(ed25519.PublicKey), nil
}

func extractROAFromMsg(msg *dns.Msg) (roa *ROA, domain string, ok bool) {
	var (
		rcert  *dns.TXT
		dnskey *dns.DNSKEY
		keySig *dns.RRSIG
		dsp    *dns.TXT
	)
	extra := msg.Extra
	for _, r := range msg.Extra {
		switch r.Header().Rrtype {
		case dns.TypeDNSKEY:
			dnskey = r.(*dns.DNSKEY)
		case dns.TypeTXT:
			txt := r.(*dns.TXT)
			if IsRCert(txt) {
				rcert = txt
			} else if IsDSP(txt) {
				dsp = txt
			} else {
				extra = append(extra, r)
			}
		case dns.TypeRRSIG:
			rrsig := r.(*dns.RRSIG)
			if rrsig.TypeCovered == dns.TypeDNSKEY {
				keySig = rrsig
			}
		default:
			extra = append(extra, r)
		}
	}
	msg.Extra = extra

	if rcert == nil || dnskey == nil || keySig == nil {
		return nil, "", false
	}
	domain = dnskey.Hdr.Name
	//domain = strings.SplitAfter(rcert.Header().Name, DNSrhineCertPrefix)[1]
	//if domain == "" {
	//	domain = "."
	//}

	return &ROA{keySig: keySig, rcert: rcert, dnskey: dnskey, dsp: dsp}, domain, true
}

func addROAToMsg(roa *ROA, msg *dns.Msg) {
	msg.Extra = append(msg.Extra, roa.dnskey)
	msg.Extra = append(msg.Extra, roa.rcert)
	msg.Extra = append(msg.Extra, roa.keySig)
	msg.Extra = append(msg.Extra, roa.dsp)
}
func IsRCert(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSrhineCertPrefix)
}

func IsDSP(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSdspprefix)
}

func rhineRRSigCheck(in *dns.Msg, key *dns.DNSKEY) bool {
	if key == nil {
		log.Warn("[RHINE] DNSKEY not found for RRSIG checking\n")
		return false
	}
	log.Debug("[RHINE] Start checking RRSIG in Answer section\n")
	if !sectionCheck(in.Answer, key) {
		return false
	}
	log.Debug("[RHINE] Start checking RRSIG in Ns section\n")
	if !sectionCheck(in.Ns, key) {
		return false
	}
	return true
}

func sectionCheck(set []dns.RR, key *dns.DNSKEY) (ok bool) {
	ok = true
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			var expired string
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				expired = "(*EXPIRED*)"
			}
			rrset := getRRset(set, rr.Header().Name, rr.(*dns.RRSIG).TypeCovered)
			if err := rr.(*dns.RRSIG).Verify(key, rrset); err != nil {
				log.Warn("[RHINE] ;- Bogus signature, %s does not validate (DNSKEY %s/%d) [%s] %s\n",
					shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), err.Error(), expired)
				ok = false
			} else {
				log.Info("[RHINE] ;+ Secure signature, %s validates (DNSKEY %s/%d) %s\n", shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), expired)
			}
		}
	}

	return ok
}

func shortSig(sig *dns.RRSIG) string {
	return sig.Header().Name + " RRSIG(" + dns.TypeToString[sig.TypeCovered] + ")"
}

func getRRset(l []dns.RR, name string, t uint16) []dns.RR {
	var l1 []dns.RR
	for _, rr := range l {
		if strings.ToLower(rr.Header().Name) == strings.ToLower(name) && rr.Header().Rrtype == t {
			l1 = append(l1, rr)
		}
	}
	return l1
}

func hash(qname string) uint64 {
	h := fnv.New64()
	h.Write([]byte(qname))
	return h.Sum64()
}
