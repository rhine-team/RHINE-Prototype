package resolver

import (
	//"bytes"
	"crypto/ed25519"

	//"crypto/x509"
	"encoding/base64"
	"errors"
	"hash/fnv"

	//"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/rhine-team/RHINE-Prototype/pkg/rhine"
)

const (
	// TODO for rootzone
	DNSrhineCertPrefix = "_rhinecert."
	DNSdspprefix       = "_dsp."
	DNSdsumprefix      = "_dsum."
	DNSproofprefix     = "_dsaproof."
	txtrhinecertprefix = "rhineCert Ed25519"
	txtDSAProofprefix  = "DSAPf "

	_RO               = 1 << 14 // RHINE OK
	defaultUDPBufSize = 2048
)

type ROA struct {
	rcert  *dns.TXT
	dnskey *dns.DNSKEY
	keySig *dns.RRSIG

	dSum     *dns.TXT
	dsaProof *dns.TXT
}

func verifyRhineROA(roa *ROA, h *DNSHandler) bool {
	_, publiKey, err := ParseVerifyRhineCertTxtEntry(roa.rcert, h)
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

func ParseVerifyDSumAndDSAProof(dsumtxt *dns.TXT, prooftxt *dns.TXT, rcert *x509.Certificate, h *DNSHandler) error {
	// Check DSum first
	if dsumtxt == nil {
		return errors.New("DSum not found")
	}
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
	if prooftxt == nil {
		return errors.New("DSAProof not found")
	}

	entriesProof := prooftxt.Txt
	entryProof := strings.Join(entriesProof, "")
	stringchunks := strings.SplitAfter(entryProof, txtDSAProofprefix)[1:]
	proofenc := strings.Join(stringchunks, "")
	proofenc = strings.ReplaceAll(proofenc, " ", "")

	proof, errProof := rhine.DeserializeMProofFromString(proofenc)
	if errProof != nil {
		return errProof
	}

	log.Info("", rcert)
	// Match DSum Rcert
	/*
		tbsbytes := rhine.ExtractTbsRCAndHash(rcert, true)
		if bytes.Compare(dsum.Cert, tbsbytes) != 0 {
			return errors.New("Cert embedded in DSum and RCert did not match")
		}
	*/

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

func ParseVerifyRhineCertTxtEntry(txt *dns.TXT, h *DNSHandler) (*x509.Certificate, ed25519.PublicKey, error) {
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
	//var CaCertPool *x509.CertPool
	//CaCertPool, _ = x509.SystemCertPool()

	//CaCert, err := os.ReadFile(certFile)
	//CaCertPool.AppendCertsFromPEM(CaCert)

	if _, err := cert.Verify(x509.VerifyOptions{
		DNSName: apexname,
		Roots:   h.trustedRoots,
	}); err != nil {
		log.Warn("Rhine Cert Verification Failed!", err)
		return nil, nil, err
	}

	return cert, cert.PublicKey.(ed25519.PublicKey), nil
}

func extractROAFromMsg(msg *dns.Msg) (roa *ROA, ok bool) {
	var (
		rcert    *dns.TXT
		dnskey   *dns.DNSKEY
		keySig   *dns.RRSIG
		dSum     *dns.TXT
		dsaProof *dns.TXT
	)
	rrs := msg.Answer
	rrs = append(rrs, msg.Extra...)
	for _, r := range rrs {
		switch r.Header().Rrtype {
		case dns.TypeDNSKEY:
			dnskey = r.(*dns.DNSKEY)
		case dns.TypeTXT:
			txt := r.(*dns.TXT)
			if IsRCert(txt) {
				rcert = txt
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
		return nil, false
	}

	return &ROA{keySig: keySig, rcert: rcert, dnskey: dnskey, dSum: dSum, dsaProof: dsaProof}, true
}

func addROAToMsg(roa *ROA, msg *dns.Msg) {
	msg.Extra = append(msg.Extra, roa.dnskey)
	msg.Extra = append(msg.Extra, roa.rcert)
	msg.Extra = append(msg.Extra, roa.keySig)
	if roa.dSum != nil {
		msg.Extra = append(msg.Extra, roa.dSum)
	}
	if roa.dsaProof != nil {
		msg.Extra = append(msg.Extra, roa.dsaProof)
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
