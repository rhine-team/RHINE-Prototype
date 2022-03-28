package common

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// This is based on CT logid package
// ID is the hash of the entitiy's public key
type ID [sha256.Size]byte

func IDFromAuthorityKeyId(x *x509.Certificate) ID {
	return ID(sha256.Sum256(x.AuthorityKeyId))
}

// Returns the ID of an entity from the given certificate file
func IDFromCertFile(file string) (ID, error) {
	cert, err := CertFromFile(file)
	if err != nil {
		return ID{}, err
	}
	pubKey := PubKeyFromCert(cert)
	return IDFromPublicKey(pubKey)
}

// Returns the ID of an entity from the given public key
func IDFromPublicKey(pubKey crypto.PublicKey) (ID, error) {
	bytePubKey, err := json.Marshal(pubKey)

	if err != nil {
		return ID{}, fmt.Errorf("failed to marshal public key: %s", err)
	}

	return ID(sha256.Sum256(bytePubKey)), nil
}

// Returns the ID of an entity from the given public key
func SubjectPublicKeyInfoDigest(cert *x509.Certificate) (ID, error) {
	return ID(sha256.Sum256(cert.RawSubjectPublicKeyInfo)), nil
}

// Returns the ID created from a DER byte slice
func CertIDFromDER(certDER []byte) ID {
	return ID(sha256.Sum256(certDER))
}

// Returns the ID created from a DER byte slice
func X509ID(x *x509.Certificate) ID {
	return CertIDFromDER(x.Raw)
}

func (id ID) Bytes() []byte {
	return id[:]
}

func (id ID) String() string {
	return fmt.Sprintf("%s", base64.StdEncoding.EncodeToString(id.Bytes()))
}
