// Functions and definitions related to x509

package common

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	// "github.com/google/trillian/merkle/maphasher"
)

// EECert extensions
var (
	OIDExtensionCALST      = asn1.ObjectIdentifier{1, 3, 500, 1}
	OIDExtensionILSLST     = asn1.ObjectIdentifier{1, 3, 500, 2}
	OIDExtensionCAMIN      = asn1.ObjectIdentifier{1, 3, 500, 3}
	OIDExtensionILSTO      = asn1.ObjectIdentifier{1, 3, 500, 4}
	OIDExtensionCATH       = asn1.ObjectIdentifier{1, 3, 500, 5}
	OIDExtensionCOPUNLKD   = asn1.ObjectIdentifier{1, 3, 500, 6}
	OIDExtensionCOPUNTRSTD = asn1.ObjectIdentifier{1, 3, 500, 7}

	OIDExtensionUNIQUE = asn1.ObjectIdentifier{1, 3, 500, 8}
)

type X509BoolExtension struct {
	Inherited bool
	Value     bool
}

type JsonCAListExt struct {
	CAList []string `json:"ca_list"`
}

type JsonILSListExt struct {
	ILSList []string `json:"ils_list"`
}

func ResolvePolicy(domain string, certificates [][]x509.Certificate) (map[string]interface{}, error) {
	policy := make(map[string]interface{})
	policy["UNIQUE"] = false
	for _, c := range certificates {
		for _, ext := range c[0].Extensions {
			if ext.Id.Equal(OIDExtensionUNIQUE) {
				if err := parseBoolExtension(domain, policy, "UNIQUE", &c[0], ext); err != nil {
					return nil, fmt.Errorf("failed to unmarshal UNIQUE extension: %s", err)
				}
			}
		}
	}
	return policy, nil
}

func (e *X509BoolExtension) GetValue() []byte {
	data, err := asn1.Marshal(*e)
	if err != nil {
		log.Fatalf("error marshalling %+v: %s", e, err)
	}
	return data
}

func parseBoolExtension(domain string, policy map[string]interface{}, key string, certificate *x509.Certificate, ext pkix.Extension) error {
	b := X509BoolExtension{}
	_, err := asn1.Unmarshal(ext.Value, &b)
	if err != nil {
		return fmt.Errorf("failed to unmarshal bool extension: %s", err)
	}

	// if the extension is not inherited, it should not be added to the policy if the subject and all SANs are parent domains
	sameDomain := IsSameDomain(domain, certificate.Subject.CommonName)
	for _, san := range certificate.DNSNames {
		if IsSameDomain(domain, san) {
			sameDomain = true
		}
	}
	if b.Inherited || sameDomain {
		policy[key] = b.Value
	}
	return nil
}

func X509ParseCertificates(chainBytes []byte) (chain []x509.Certificate, err error) {
	var pointerChain []*x509.Certificate
	pointerChain, err = x509.ParseCertificates(chainBytes)
	if err != nil {
		return
	}
	for _, p := range pointerChain {
		chain = append(chain, *p)
	}
	return
}

// Read Public Key from file
func LoadPK(file string) (interface{}, error) {
	content, err := ioutil.ReadFile(file)

	if err != nil {
		LogError("Cannot read from "+file+": %s", err)
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, errors.New("nil pem block")
	}

	if block.Type == "PUBLIC KEY" {
		return x509.ParsePKIXPublicKey(block.Bytes)
	} else {
		return nil, fmt.Errorf("file %s does not contain a public key", file)
	}
}

func WriteCertBytesToFile(certBytes []byte, f string) {
	certOut, err := os.Create(f)
	if err != nil {
		log.Fatalf("Failed to open %s for writing: %s", f, err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %s", err)
	}
	log.Printf("wrote %s\n", f)
}

// Read a PEM encoded private or public key from a
// given file
func KeyFromPEM(fileName string) ([]byte, error) {
	var ret []byte
	content, err := ioutil.ReadFile(fileName)

	if err != nil {
		return nil, fmt.Errorf("failed to read from %s: %s", fileName, err)
	}

	for {
		var block *pem.Block
		block, content = pem.Decode(content)

		if block == nil {
			return nil, fmt.Errorf("no pem block in %s", fileName)
		}

		if block.Type == "EC PRIVATE KEY" {
			ret = block.Bytes
			break
		} else if block.Type == "PUBLIC KEY" {
			ret = block.Bytes
			break
		}
	}

	return ret, nil
}

func ReadEECert(request *CRReq) (EECert, error) {
	byteEECert := request.EECert
	eecert, err := x509.ParseCertificates(byteEECert)
	return eecert, err
}

func CertFromFile(fileName string) (*x509.Certificate, error) {
	byteCert, err := EECertFromPEM(fileName)
	if err != nil {
		return nil, fmt.Errorf("EECertFromPEM failed: %s", err)
	}

	certificate, err := x509.ParseCertificate(byteCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", err)
	}
	return certificate, nil
}

func PubKeyFromCert(certificate *x509.Certificate) interface{} {
	pubKey := certificate.PublicKey
	return pubKey
}

func X509CertToString(certificate *x509.Certificate) string {
	return fmt.Sprintf("<cert domains=%s, serial=%d>", DomainsFromX509Cert(certificate), certificate.SerialNumber)
}

func X509CertChainToString(chain []x509.Certificate) string {
	return fmt.Sprintf("<Chain[%d] rootAKI=%x %s>", len(chain), chain[len(chain)-1].AuthorityKeyId, X509CertToString(&chain[0]))
}

func X509CertChainToStringExtended(chain []x509.Certificate) string {
	out := fmt.Sprintf("<Chain[%d] ", len(chain))
	for i, x := range chain {
		if i != 0 {
			out += ", "
		}
		out += fmt.Sprintf("<cert subject=%s, domains=%s, serial=%d, SKI=%x, AKI=%x>", x.Subject.String(), DomainsFromX509Cert(&x), x.SerialNumber, x.SubjectKeyId, x.AuthorityKeyId)
	}
	return out + ">"
}

// Read an EECert from a given file.
// Iterate through multiple PEM blocks.
func EECertFromPEM(fileName string) (ByteEECert, error) {
	var bytesCerts []byte
	content, err := ioutil.ReadFile(fileName)

	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %s", fileName, err)
	}

	for {
		var block *pem.Block
		block, content = pem.Decode(content)

		if block == nil {
			if len(bytesCerts) == 0 {
				return nil, fmt.Errorf("no pem block in %s", fileName)
			} else {
				return bytesCerts, nil
			}
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s contains data other than certificate", fileName)
		}

		bytesCerts = append(bytesCerts, block.Bytes...)
	}
}

func X509CertChainBytesFromPEM(fileName string) ([]byte, error) {
	var bytesCerts []byte
	content, err := ioutil.ReadFile(fileName)

	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %s", fileName, err)
	}

	for {
		var block *pem.Block
		block, content = pem.Decode(content)

		if block == nil {
			if len(bytesCerts) == 0 {
				return nil, fmt.Errorf("no pem block in %s", fileName)
			} else {
				return bytesCerts, nil
			}
		}

		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%s contains data other than certificate", fileName)
		}

		bytesCerts = append(bytesCerts, block.Bytes...)
	}
}

// Read an EECert from a given file.
// Iterate through multiple PEM blocks.
func X509CertFromPEM(fileName string) (*x509.Certificate, error) {
	content, err := ioutil.ReadFile(fileName)

	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %s", fileName, err)
	}

	var block *pem.Block
	block, _ = pem.Decode(content)

	if block == nil {
		return nil, fmt.Errorf("no pem block in %s", fileName)
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s contains data other than certificate", fileName)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func DomainsFromX509Cert(cert *x509.Certificate) []string {
	var domains []string
	domains = append(domains, strings.ToLower(cert.Subject.CommonName))
	for _, d := range cert.DNSNames {
		domains = append(domains, strings.ToLower(d))
	}
	return domains
}

func X509ContainsDomain(cert *x509.Certificate, domain string) bool {
	for _, d := range DomainsFromX509Cert(cert) {
		if d == domain {
			return true
		}
	}
	return false
}

func X509MatchesDomain(cert *x509.Certificate, domain string) bool {
	for _, d := range DomainsFromX509Cert(cert) {
		if IsSameDomain(d, domain) {
			return true
		}
	}
	return false
}

func MapKeysFromX509Cert(cert *x509.Certificate) [][]byte {
	var mapKeys [][]byte
	for _, d := range DomainsFromX509Cert(cert) {
		mapKeys = append(mapKeys, []byte(d))
	}
	return mapKeys
}

// assume that cert[0] is endpoint certificate and cert[len(cert)-1] is certificate issued by CA and CA is in the system's certificate pool
func X509Verify(cert []x509.Certificate) ([][]*x509.Certificate, error) {
	r, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	for _, c := range X509GetCerts("/home/cyrill/go/src/github.com/cyrill-k/trustflex/data", "ca\\d+_cert.pem") {
		r.AddCert(c)
	}

	// gradually add certs from chain and attempt to verify certificate
	p := x509.NewCertPool()
	var verifiedChains [][]*x509.Certificate
	// if all verification attempts fail, return last error (i.e., error when attempting to verify with all non self-signed certificates)
	var lastError error
	succeeded := false
	for _, x := range cert[1:] {
		if !X509CertIsSelfSigned(x) {
			//Debug("Adding intermediate certificate and verify: %s", X509CertToString(&x))
			p.AddCert(&x)
			var newChains [][]*x509.Certificate
			newChains, lastError = cert[0].Verify(x509.VerifyOptions{Intermediates: p, Roots: r})
			if lastError == nil && len(newChains) > 0 {
				succeeded = true
				verifiedChains = append(verifiedChains, newChains...)
				// a single successful verification is enough
				break
			}
		}
	}
	if succeeded {
		return verifiedChains, nil
	} else {
		return nil, lastError
	}
}

func X509CertIsSelfSigned(c x509.Certificate) bool {
	return len(c.AuthorityKeyId) == 0 || bytes.Compare(c.SubjectKeyId, c.AuthorityKeyId) == 0
}

func X509GetCerts(certFolder, regex string) []*x509.Certificate {
	var certs []*x509.Certificate

	re, err := regexp.Compile(regex)
	LogError("Failed to create regex: %s", err)

	err = filepath.Walk(certFolder, func(path string, info os.FileInfo, err error) error {
		if re.Find([]byte(path)) != nil {
			// log.Printf("%s, %d, %s, %s", path, info.Size(), err, re.Find([]byte(path)))
			cert, err := X509CertFromPEM(path)
			LogError("Failed to read cert from file: %s", err)

			certs = append(certs, cert)
		}
		return nil
	})
	return certs
}

// Used by both CAs and ILS during Certificate Update
func VerifyUpdateRequirements(old, new []*x509.Certificate, firstILS, firstCA, secondCA string) error {
	log.Println("Verifying update requirements")

	var newCas JsonCAListExt
	var newIls JsonILSListExt
	var newMin int
	var err error
	for _, cert := range new {
		newExts := cert.Extensions

		for _, ext := range newExts {
			if ext.Id.Equal(OIDExtensionCALST) {
				err := json.Unmarshal(ext.Value, &newCas.CAList)

				if err != nil {
					return fmt.Errorf("failed to unmarshal CA list extension: %s", err)
				}

				if !SliceIncludes(newCas.CAList, firstCA) || !SliceIncludes(newCas.CAList, firstCA) {
					return errors.New("involved CAs are not in CA_LIST")
				}

			} else if ext.Id.Equal(OIDExtensionILSLST) {
				err := json.Unmarshal(ext.Value, &newIls.ILSList)

				if err != nil {
					return fmt.Errorf("failed to unmarshal ILS list extension: %s", err)
				}

				if !SliceIncludes(newIls.ILSList, firstILS) {
					return fmt.Errorf("involved ILS is not in ILS_LIST: %s", firstILS)
				}

			} else if ext.Id.Equal(OIDExtensionCAMIN) {
				newMin, err = strconv.Atoi(string(ext.Value))

				if err != nil {
					return fmt.Errorf("failed to convert CA_MIN extension: %s", err)
				}

				if len(new) < newMin {
					return fmt.Errorf("EECert should have at least %d certificates, but only has %d", newMin, len(new))
				}
			}
		}

	}
	var oldCas JsonCAListExt
	var oldIls JsonILSListExt
	var oldMin int
	var oldCOP, oldCOPLKD int64
	for _, cert := range old {
		oldExts := cert.Extensions

		for _, ext := range oldExts {
			if ext.Id.Equal(OIDExtensionCALST) {
				err := json.Unmarshal(ext.Value, &oldCas.CAList)

				if err != nil {
					return fmt.Errorf("failed to unmarshal CA list extension: %s", err)
				}
			} else if ext.Id.Equal(OIDExtensionILSLST) {
				err := json.Unmarshal(ext.Value, &oldIls.ILSList)

				if err != nil {
					return fmt.Errorf("failed to unmarshal ILS list extension: %s", err)
				}

			} else if ext.Id.Equal(OIDExtensionCAMIN) {
				oldMin, err = strconv.Atoi(string(ext.Value))

				if err != nil {
					return fmt.Errorf("failed to convert CA_MIN extension: %s", err)
				}
			} else if ext.Id.Equal(OIDExtensionCOPUNTRSTD) {
				oldCOP, err = strconv.ParseInt(string(ext.Value), 10, 64)

				if err != nil {
					return fmt.Errorf("failed to convert COP_UNTRUSTED extension: %s", err)
				}
			} else if ext.Id.Equal(OIDExtensionCOPUNLKD) {
				oldCOPLKD, err = strconv.ParseInt(string(ext.Value), 10, 64)

				if err != nil {
					return fmt.Errorf("failed to convert COP_UNLINKED extension: %s", err)
				}
			}
		}
	}

	if !SliceIncludes(oldIls.ILSList, firstILS) || !SliceIncludes(oldCas.CAList, firstCA) ||
		!SliceIncludes(oldCas.CAList, secondCA) {
		return fmt.Errorf("untrusted entities with respect to old EECert, cool-off period set to %d", oldCOP)
	}

	if len(new) < oldMin {
		return fmt.Errorf("new EECert should have at least %d (old CA_MIN) certificates, but only has %d", oldMin, len(new))
	}

	signedByOld := new[len(new)-1] // last certificate of new EECert is the one signed by the old private key
	// public keys are the same, so take old[0]
	err = signedByOld.CheckSignatureFrom(old[0])
	if err != nil {
		return fmt.Errorf("failed to verify old EECert signature over new one, cool-off period set to %d: %s", oldCOPLKD, err)
	}

	return nil
}
