package keyManager

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"github.com/rhine-team/RHINE-Prototype/common"
)

func CreateRSAKey(path string) error {
	PrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	err = common.StoreRSAPrivateKeyPEM(PrivateKey, path)
	if err != nil {
		return err
	}
	return nil
}

func CreateEd25519Key(path string) error {
	_, privatekey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	err = common.StorePrivateKeyEd25519(path, privatekey)
	if err != nil {
		return err
	}
	return nil
}

func CreateSelfSignedCACertificate(alg string, keyPath string, certPath string) error {
	var privKey crypto.Signer
	switch alg {
	case "RSA":
		var err error
		privKey, err = common.LoadRSAPrivateKeyPEM(keyPath)
		if err != nil {
			return err
		}
	case "Ed25519":
		var err error
		privKey, err = common.LoadPrivateKeyEd25519(keyPath)
		if err != nil {
			return err
		}
	}
	certbytes, err := common.CreateSelfSignedCertCA(privKey.Public(), privKey)
	if err != nil {
		return err
	}
	err = common.StoreCertificatePEM(certPath, certbytes)
	if err != nil {
		return err
	}

	return nil
}