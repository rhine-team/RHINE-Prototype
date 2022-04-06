package rhine

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

type RhineSig struct {
	Algorithm RhineSupportedAlgorithm
	Data      []byte
	Signature []byte
}

type RhineSupportedAlgorithm int

const (
	ED25519      RhineSupportedAlgorithm = 0
	RSAPSSSHA256 RhineSupportedAlgorithm = 1
)

func (rs RhineSig) Sign(priv interface{}) error {
	var err error = nil

	switch priv.(type) {
	case ed25519.PrivateKey:
		rs.Signature = ed25519.Sign(priv.(ed25519.PrivateKey), rs.Data)
		rs.Algorithm = ED25519

	case *rsa.PrivateKey:
		sha256 := sha256.New()
		sha256.Write(rs.Data)
		hash := sha256.Sum(nil)
		rs.Signature, err = rsa.SignPSS(rand.Reader, priv.(*rsa.PrivateKey), crypto.SHA256, hash, nil)
		rs.Algorithm = RSAPSSSHA256
	default:
		err = errors.New("unsupported private key type")
	}

	return err
}

func (rs RhineSig) Verify(pub crypto.PublicKey) bool {

	switch pub.(type) {
	case ed25519.PublicKey:
		ok := ed25519.Verify(pub.(ed25519.PublicKey), rs.Data, rs.Signature)
		return ok

	case *rsa.PublicKey:
		sha256 := sha256.New()
		sha256.Write(rs.Data)
		hash := sha256.Sum(nil)
		err := rsa.VerifyPSS(pub.(*rsa.PublicKey), crypto.SHA256, hash, rs.Signature, nil)
		if err != nil {
			return false
		}
	}

	return false
}

