package common

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"github.com/golang/protobuf/ptypes/timestamp"
	ct "github.com/google/certificate-transparency-go"
)

// An EECert is a sequence of PEM encoded x509 Certificates
type EECert []*x509.Certificate
type ByteEECert []byte

// BFTEECert is specifically used during the BFT protocol,
// since it allows to distinguish between a new addition
// and an update
type BFTEECert struct {
	IsNew  bool
	EECert ByteEECert
}

// LogEntry is returned by the GetEntries interface
type LogEntry struct {
	LeafValue []byte               `json:"value"`
	Timestamp *timestamp.Timestamp `json:"timestamp"`
}

// Returns the key under which the EECert is/will be stored
// in the Trillian Map
func MapKeyFromByteEECert(byteEECert ByteEECert) ([]byte, error) {
	eecert, err := x509.ParseCertificates(byteEECert)
	if err != nil {
		return nil, err
	}

	return MapKeyFromEECert(eecert), nil
}

func MapKeyFromEECert(eeCert []*x509.Certificate) []byte {
	domain := eeCert[0].Subject.CommonName
	return MapKeyFromDomain(domain)
}

func MapKeyFromDomain(domain string) []byte {
	key := sha256.Sum256([]byte(domain))
	return key[:]
}

func LeafHashFromByteEECert(byteEECert []byte) ([]byte, error) {
	jsonCert, err := json.Marshal(byteEECert)
	if err != nil {
		return nil, err
	}

	hashedEECert := sha256.Sum256(append([]byte{ct.TreeLeafPrefix}, jsonCert...))
	return hashedEECert[:], nil
}

// Returns the domain given an encoded EECert
func DomainFromByteEECert(byteEECert ByteEECert) (string, error) {
	eecert, err := x509.ParseCertificates(byteEECert)
	if err != nil {
		return "", err
	}

	return eecert[0].Subject.CommonName, nil
}
