package main

import (
	"bytes"
	"crypto/ed25519"

	//"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	//"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/rhine-team/RHINE-Prototype/pkg/rhine"

	"github.com/miekg/dns"
)

const (
	DNSrhineCertPrefix = "_rhinecert."
	DNSdspprefix       = "_dsp."
	DNSdsumprefix      = "_dsum."
	DNSproofprefix     = "_dsaproof."
	txtDSAProofprefix  = "DSAPf "

	txtrhinecertprefix = "rhineCert Ed25519"
	txtsigvalueprefix  = "rhineSig "
	defaultUDPBufSize  = 2048
)

type ROA struct {
	rcert  *dns.TXT
	dsp    *dns.TXT
	dnskey *dns.DNSKEY
	keySig *dns.RRSIG

	dSum     *dns.TXT
	dsaProof *dns.TXT
}

func Size(m *dns.Msg) {
	o := m.IsEdns0()
	if o != nil {
		o.SetUDPSize(defaultUDPBufSize)
		return
	}

	o = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.SetUDPSize(defaultUDPBufSize)
	m.Extra = append(m.Extra, o)
}

func verifyRhineROA(roa *ROA, h *Helper) bool {
	rcert, publiKey, err := ParseVerifyRhineCertTxtEntry(roa.rcert, h)
	if err != nil {
		fmt.Printf("[RHINE] RCert parse faild, error: %s\n", err.Error())
		return false
	}
	fmt.Printf("[RHINE] RCert successfully parsed\n")

	// Check DSum and DSAProof
	err = ParseVerifyDSumAndDSAProof(roa.dSum, roa.dsaProof, rcert, h)
	if err != nil {
		log.Println("Error ", err.Error())
		return false
	}

	if err := roa.keySig.VerifyWithPublicKey(publiKey, []dns.RR{roa.dnskey}); err != nil {
		fmt.Printf("[RHINE] RhineSig verification failed, %s \n", err)
		return false
	} else {
		fmt.Printf("[RHINE] RhineSig successfully verified\n")
		return true
	}
}

func ParseVerifyDSumAndDSAProof(dsumtxt *dns.TXT, prooftxt *dns.TXT, rcert *x509.Certificate, h *Helper) error {
	// Check DSum first
	entries := dsumtxt.Txt
	entry := strings.Join(entries, "")

	dsum, err := rhine.DeserializeDSumNRFromString(entry)
	if err != nil {
		return err
	}

	if len(dsum.LoggerList) < 1 || len(dsum.Signatures) < 1 || len(dsum.LoggerList) != len(dsum.Signatures) {
		return errors.New("No singature/log list in DSum")
	}

	for _, logger := range dsum.LoggerList {
		if dsum.VerifyOne(logger, h.loggerNameToPubKey[logger]) != nil {
			return errors.New("Signature does not match for at least one DSum signature")
		}
	}

	// Check DSAProof
	entriesProof := prooftxt.Txt
	entryProof := strings.Join(entriesProof, "")
	stringchunks := strings.SplitAfter(entryProof, txtDSAProofprefix)[1:]
	proofenc := strings.Join(stringchunks, "")
	proofenc = strings.ReplaceAll(proofenc, " ", "")

	proof, errProof := rhine.DeserializeMProofFromString(proofenc)
	if errProof != nil {
		return errProof
	}

	// Match DSum Rcert
	tbsbytes := rhine.ExtractTbsRCAndHash(rcert, true)
	if bytes.Compare(dsum.Cert, tbsbytes) != 0 {
		return errors.New("Cert embedded in DSum and RCert did not match")
	}

	// TODO T recent enough and revocation

	if !rhine.CheckINDSetAlt(dsum.Alv) {
		// Accept the answer
		return nil
	}

	// Fast track cases
	if rhine.CheckTERSetAlt(dsum.Alv) || rhine.CheckEOISetAlt(dsum.Alv) {
		return nil
	} else if rhine.CheckDOLSetAlt(dsum.Alv) {
		return errors.New("Not a valid answer (Dol Set)")
	} else {
		if proof.Ptype == rhine.ProofOfAbsence {
			boolres, errres := proof.VerifyMPathProof(dsum.Dacc.Roothash, dsum.Dacc.Zone)
			if boolres && errres == nil {
				return nil
			}
		} else if proof.Ptype == rhine.ProofOfPresence {
			boolres, errres := proof.VerifyMPathProof(dsum.Dacc.Roothash, dsum.Dacc.Zone)
			if boolres && errres == nil && !rhine.CheckINDSetAlt(proof.Lcontent.Start.Alv) {
				return nil
			} else {
				return errors.New("Rejected in PofPresence case")
			}
		} else {
			return errors.New("Unsupported Proof Type")
		}
	}
	return errors.New("No success")
}

func ParseVerifyRhineCertTxtEntry(txt *dns.TXT, h *Helper) (*x509.Certificate, ed25519.PublicKey, error) {
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

	name := txt.Header().Name
	apexname := strings.SplitAfter(name, DNSrhineCertPrefix)[1]

	//var CaCertPool *x509.CertPool
	//CaCertPool, _ = x509.SystemCertPool()

	//CaCertPool.AppendCertsFromPEM(CaCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		DNSName: apexname,
		Roots:   h.trustedRoots,
	}); err != nil {
		fmt.Println("Rhine Cert Verification Failed!", err)
		return nil, nil, err
	}

	return cert, cert.PublicKey.(ed25519.PublicKey), nil
}

func extractROAFromMsg(msg *dns.Msg) (roa *ROA, domain string, ok bool) {
	var (
		rcert  *dns.TXT
		dnskey *dns.DNSKEY
		keySig *dns.RRSIG
		//dsp      *dns.TXT
		dSum     *dns.TXT
		dsaProof *dns.TXT
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
				//dsp = txt
			} else if IsDSum(txt) {
				dSum = txt
			} else if IsDSAProof(txt) {
				dsaProof = txt
			}
		case dns.TypeRRSIG:
			rrsig := r.(*dns.RRSIG)
			if rrsig.TypeCovered == dns.TypeDNSKEY {
				keySig = rrsig
			}
		}
	}
	if rcert == nil || dnskey == nil || keySig == nil {
		fmt.Printf("[RHINE] ;? Correct ROA not found in Msg\n")
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
	fmt.Printf("[RHINE] ROA successfully extracted from response\n")
	return &ROA{keySig: keySig, rcert: rcert, dnskey: dnskey, dSum: dSum, dsaProof: dsaProof}, domain, true
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

func IsDSum(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSdsumprefix)
}

func IsDSAProof(txt *dns.TXT) bool {
	return strings.HasPrefix(txt.Header().Name, DNSproofprefix)
}

func IsRhineSig(txt *dns.TXT) bool {
	entries := txt.Txt
	entry := strings.Join(entries, " ")
	return strings.HasPrefix(entry, txtsigvalueprefix)
}
