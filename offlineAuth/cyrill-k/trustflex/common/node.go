package common

import (
	"crypto/sha256"
	"crypto/x509"
)

// An EECert is a sequence of PEM encoded x509 Certificates
type Cert *x509.Certificate
type ByteCert []byte

func GenerateMapKey(treeNonce []byte, domain string) []byte {
	h := sha256.New()
	h.Write(treeNonce)
	h.Write([]byte(domain))
	return h.Sum(nil)
}
