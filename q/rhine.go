package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

const (
	rootzone           = ""
	DNSrhineCertPrefix = "_rhinecert."
	DNSdspprefix       = "_dsp."

	txtrhinecertprefix = "rhineCert Ed25519"
	txtsigvalueprefix  = "rhineSig "

	_RO               = 1 << 14 // RHINE OK
	defaultUDPBufSize = 2048
	defaultCacheSize  = 1024 * 256
)

type Delegation struct {
	rcert  *dns.TXT
	dsp    *dns.TXT
	dnskey *dns.DNSKEY
	keySig *dns.TXT
}

func verifyRhineDelegation(deleg *Delegation) bool {
	_, publiKey, err := ParseVerifyRhineCertTxtEntry(deleg.rcert)
	if err != nil {
		fmt.Printf("[RHINE] RCert parse faild, error: %s\n", err.Error())
		return false
	}
	fmt.Printf("[RHINE] RCert successfully parsed\n")

	// TODO add more key type
	if ok := VerifySig(publiKey, []dns.RR{deleg.dnskey}, deleg.keySig); ok {
		fmt.Printf("[RHINE] RhineSig successfully verified\n")
		return true
	} else {
		fmt.Printf("[RHINE] RhineSig verification failed\n")
		return false
	}
}

// SetRoOpt sets the RO (RHINE OK) bit.
// If we pass an argument, set the DO bit to that value.
// It is possible to pass 2 or more arguments. Any arguments after the 1st is silently ignored.
func SetRoOpt(rr *dns.OPT, do ...bool) {
	if len(do) == 1 {
		if do[0] {
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

func ParseVerifyRhineCertTxtEntry(txt *dns.TXT) (*x509.Certificate, ed25519.PublicKey, error) {
	//TODO support other key types
	entries := txt.Txt
	entry := strings.Join(entries, " ")
	certstringchunks := strings.SplitAfter(entry, txtrhinecertprefix)[1:]
	encodedcert := strings.Join(certstringchunks, "")
	encodedcert = strings.ReplaceAll(encodedcert, " ", "")

	certdecoded, _ := base64.StdEncoding.DecodeString(encodedcert)

	cert, err := x509.ParseCertificate(certdecoded)
	if err != nil {
		fmt.Println("Parsing Rhine Cert failed! ", err)
		return nil, nil, err
	}

	// TODO(lou): Enable Cert verification later
	//name := txt.Header().Name
	//apexname := strings.SplitAfter(name, DNSrhineCertPrefix)[1]
	//var CaCertPool *x509.CertPool
	//CaCertPool, _ = x509.SystemCertPool()
	//
	//CaCertPool.AppendCertsFromPEM([]byte("-----BEGIN CERTIFICATE-----\nMIIBJjCB2aADAgECAgEBMAUGAytlcDAbMRkwFwYDVQQDExBSSElORSBFWEFNUExF\nIENBMB4XDTIyMDIyMTA5MDI1NVoXDTIzMDIxMjA5MDI1NVowGzEZMBcGA1UEAxMQ\nUkhJTkUgRVhBTVBMRSBDQTAqMAUGAytlcAMhAFq9YoSG/zv2npflvTwmog9Ymijs\nK0NDTDYFgTbGxyrto0IwQDAOBgNVHQ8BAf8EBAMCAoQwDwYDVR0TAQH/BAUwAwEB\n/zAdBgNVHQ4EFgQUXcJH29E2egUuSdhJFoy/kJQDlcwwBQYDK2VwA0EAxB2JHVh+\nN7o3RTBCp7wOWDlGePd0xuhRhU4GEJs4CTxGgLbcyX1iIzF7kJ1qCmp+y180PAJe\nxqM22eY3hKQFAQ==\n-----END CERTIFICATE-----"))
	//
	//if _, err := cert.Verify(x509.VerifyOptions{
	//	DNSName: apexname,
	//	Roots:   CaCertPool,
	//}); err != nil {
	//	fmt.Println("Rhine Cert Verification Failed!", err)
	//	return nil, nil, err
	//}

	return cert, cert.PublicKey.(ed25519.PublicKey), nil
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

func extractDelegationFromMsg(msg *dns.Msg) (delegation *Delegation, domain string, ok bool) {
	var (
		rcert  *dns.TXT
		dnskey *dns.DNSKEY
		keySig *dns.TXT
		dsp    *dns.TXT
	)
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
			} else if IsRhineSig(txt) {
				keySig = txt
			}
		}
	}
	if rcert == nil || dnskey == nil || keySig == nil {
		fmt.Printf("[RHINE] ;? Correct delegation not found in Msg\n")
		if rcert == nil {
			fmt.Printf("[RHINE] ;? RCert is null\n")
		}
		if dnskey == nil {
			fmt.Printf("[RHINE] ;? DNSKEY is null\n")
		}
		if keySig == nil {
			fmt.Printf("[RHINE] ;? keySig is null\n")
		}
		return nil, "", false
	}
	domain = strings.SplitAfter(rcert.Header().Name, DNSrhineCertPrefix)[1]
	//if apexname == "" {
	//	apexname = "."
	//}
	fmt.Printf("[RHINE] Delegation successfully extracted from response\n")
	return &Delegation{keySig: keySig, rcert: rcert, dnskey: dnskey, dsp: dsp}, domain, true
}

func rhineRRSigCheck(in *dns.Msg, key *dns.DNSKEY) {
	if key == nil {
		fmt.Printf("[RHINE] DNSKEY not found for RRSIG checking\n")
		return
	}
	fmt.Printf("[RHINE] Start checking RRSIG in Answer section\n")
	rhineSectionCheck(in.Answer, key)
	fmt.Printf("[RHINE] Start checking RRSIG in Ns section\n")
	rhineSectionCheck(in.Ns, key)
	fmt.Printf("[RHINE] Start checking RRSIG in Extra section\n")
	rhineSectionCheck(in.Extra, key)
}

func rhineSectionCheck(set []dns.RR, key *dns.DNSKEY) {
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			var expired string
			if !rr.(*dns.RRSIG).ValidityPeriod(time.Now().UTC()) {
				expired = "(*EXPIRED*)"
			}
			rrset := getRRset(set, rr.Header().Name, rr.(*dns.RRSIG).TypeCovered)
			if err := rr.(*dns.RRSIG).Verify(key, rrset); err != nil {
				fmt.Printf("[RHINE] ;- Bogus signature, %s does not validate (DNSKEY %s/%d) [%s] %s\n",
					shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), err.Error(), expired)
			} else {
				fmt.Printf("[RHINE] ;+ Secure signature, %s validates (DNSKEY %s/%d) %s\n", shortSig(rr.(*dns.RRSIG)), key.Header().Name, key.KeyTag(), expired)
			}
		}
	}
}

func IsRCert(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSrhineCertPrefix)
}

func IsDSP(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSdspprefix)
}

func IsRhineSig(txt *dns.TXT) bool {
	entries := txt.Txt
	entry := strings.Join(entries, " ")
	return strings.HasPrefix(entry, txtsigvalueprefix)
}
