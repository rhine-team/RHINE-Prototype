package rhine

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"log"
)

const (
	DLGTAPPROVAL string = "DLGT_APPROVAL"
	LOGCONFIRM   string = "LOGCONFIRM"
)

type RhineSig struct {
	Algorithm   RhineSupportedAlgorithm
	Data        []byte
	Signature   []byte
	DataPostfix []byte
}

type RhineSupportedAlgorithm int

const (
	ED25519      RhineSupportedAlgorithm = 0
	RSAPSSSHA256 RhineSupportedAlgorithm = 1
)

func (rs *RhineSig) Sign(priv interface{}) error {
	var err error = nil

	signData := rs.Data
	if rs.DataPostfix != nil {
		signData = append(signData, rs.DataPostfix...)
	}

	switch priv.(type) {
	case ed25519.PrivateKey:
		rs.Signature = ed25519.Sign(priv.(ed25519.PrivateKey), signData)
		rs.Algorithm = ED25519

	case *rsa.PrivateKey:
		sha256 := sha256.New()
		sha256.Write(signData)
		hash := sha256.Sum(nil)
		rs.Signature, err = rsa.SignPSS(rand.Reader, priv.(*rsa.PrivateKey), crypto.SHA256, hash, nil)
		rs.Algorithm = RSAPSSSHA256
	default:
		err = errors.New("unsupported private key type")
	}

	if err != nil {
		log.Println("Error during rhine signature signing: ", err)
	}

	return err
}

func (rs *RhineSig) Verify(pub crypto.PublicKey) bool {
	signData := rs.Data
	if rs.DataPostfix != nil {
		signData = append(signData, rs.DataPostfix...)
	}

	switch pub.(type) {
	case ed25519.PublicKey:
		ok := ed25519.Verify(pub.(ed25519.PublicKey), signData, rs.Signature)
		return ok

	case *rsa.PublicKey:
		sha256 := sha256.New()
		sha256.Write(signData)
		hash := sha256.Sum(nil)
		err := rsa.VerifyPSS(pub.(*rsa.PublicKey), crypto.SHA256, hash, rs.Signature, nil)
		if err != nil {
			log.Println("Error during RSA signature verification: ", err)
			return false
		}
	}

	return true
}
