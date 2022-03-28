// A MapEntry stores certificates valid for a specific (wildcard-)domain and possibly the root of a tree for subdomains

package tclient

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/common"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMapEntryTypeMarshal(t *testing.T) {
	c := testCreateCertificate()
	if c == nil {
		t.Errorf("Couldn't create test certificate")
	}

	r := []byte{1, 2, 3, 4}
	in := MapEntryType{Certificates: [][]x509.Certificate{[]x509.Certificate{*c}}, WildcardCertificates: nil, Revocations: nil, WildcardRevocations: nil, SubtreeRoot: r}
	testEntry(t, in)

	r2 := []byte{}
	in2 := MapEntryType{Certificates: [][]x509.Certificate{[]x509.Certificate{*c}}, WildcardCertificates: nil, Revocations: nil, WildcardRevocations: nil, SubtreeRoot: r2}
	testEntry(t, in2)
}

func testEntry(t *testing.T, in MapEntryType) {
	inEncoded, err := in.MarshalBinary()
	if err != nil {
		t.Errorf("Couldn't marshal MapEntryType: %s", err)
	}
	var out MapEntryType
	err = out.UnmarshalBinary(inEncoded)
	if err != nil {
		t.Errorf("Couldn't unmarshal MapEntryType: %s", err)
	}
	if !testMapEntryTypeIsEqual(in, out) {
		t.Errorf("MapEntryType changed after marshal/unmarshal: %+v != %+v: %s", in.ToString(), out.ToString(), err)
	}
}

func testCreateCertificate() *x509.Certificate {
	priv, _ := GenerateKeys()
	d := CreateCertificate(priv, PublicKey(priv), nil, strings.Split("CH,Example,ZH,www.example.ch", ","))
	c, err := x509.ParseCertificate(d)
	if err != nil {
		return nil
	}
	return c
}

func testMapEntryTypeIsEqual(a, b MapEntryType) bool {
	if len(a.Certificates) != len(b.Certificates) {
		return false
	}
	if len(a.WildcardCertificates) != len(b.WildcardCertificates) {
		return false
	}
	if len(a.Revocations) != len(b.Revocations) {
		return false
	}
	if len(a.WildcardRevocations) != len(b.WildcardRevocations) {
		return false
	}
	if len(a.SubtreeRoot) != len(b.SubtreeRoot) {
		return false
	}

	for i, _ := range a.Certificates {
		if len(a.Certificates[i]) != len(b.Certificates[i]) {
			return false
		}
		for j, _ := range a.Certificates[i] {
			if (a.Certificates[i][j].SerialNumber).Cmp(b.Certificates[i][j].SerialNumber) != 0 {
				return false
			}
		}
	}
	for i, _ := range a.WildcardCertificates {
		if len(a.WildcardCertificates[i]) != len(b.WildcardCertificates[i]) {
			return false
		}
		for j, _ := range a.WildcardCertificates[i] {
			if (a.WildcardCertificates[i][j].SerialNumber).Cmp(b.WildcardCertificates[i][j].SerialNumber) != 0 {
				return false
			}
		}
	}
	for i, ai := range a.Revocations {
		if (&ai.SerialNumber).Cmp(&b.Revocations[i].SerialNumber) != 0 {
			return false
		}
	}
	for i, ai := range a.WildcardRevocations {
		if (&ai.SerialNumber).Cmp(&b.WildcardRevocations[i].SerialNumber) != 0 {
			return false
		}
	}
	if !bytes.Equal(a.SubtreeRoot, b.SubtreeRoot) {
		return false
	}
	return true
}

func PublicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func CreateCertificate(priv_signer, pub_signee interface{}, caCert *x509.Certificate, subj []string) []byte {
	notBefore := time.Now()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s", err)
	}

	d, err := time.ParseDuration("1h")
	if err != nil {
		log.Fatalf("couldn't parse duration: %s", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:      append([]string{}, subj[0]),
			Organization: append([]string{}, subj[1]),
			Locality:     append([]string{}, subj[2]),
			CommonName:   subj[3],
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(d),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split("localhost", ",")
	for _, h := range hosts {
		if h == "" {
			// do not add empty domains
		} else if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if true {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	var derBytes []byte
	if true {
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, pub_signee, priv_signer)
		common.LogError("Failed to create self signed certificate: %s", err)
	} else {
		derBytes, err = x509.CreateCertificate(rand.Reader, &template, caCert, pub_signee, priv_signer)
		common.LogError("Failed to create certificate: %s", err)
	}

	return derBytes
}

func GenerateKeys() (interface{}, error) {
	var priv interface{}
	var err error
	switch "P256" {
	case "":
		priv, err = rsa.GenerateKey(rand.Reader, 4000)
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)

	default:
		fmt.Fprintf(os.Stderr, "Unrecognized elliptic curve: %q", "P256")
		os.Exit(1)
	}
	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
	}
	return priv, err
}
