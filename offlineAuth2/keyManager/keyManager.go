package keyManager

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"
)

// These functions are from the old offlineAuth version

func CreateRSAKey(path string, pubkey bool) error {
	PrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	pbkey = privKey.(*rsa.PrivateKey).Public()

	if err != nil {
		return err
	}

	if pubkey {
		pa := strings.Split(path, ".")[0]
		err = rhine.StoreRSAPublicKeyPEM(pbkey, pa+"_pub.pem")

		if err != nil {
			return err
		}
	}

	err = rhine.StoreRSAPrivateKeyPEM(PrivateKey, path)
	if err != nil {
		return err
	}
	return nil
}

func CreateEd25519Key(path string, pubkey bool) error {
	pbkey, privatekey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		return err
	}

	if pubkey {
		pa := strings.Split(path, ".")[0]
		err = rhine.StorePublicKeyEd25519(pa+"_pub.pem", pbkey)

		if err != nil {
			return err
		}
	}

	err = rhine.StorePrivateKeyEd25519(path, privatekey)
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
		privKey, err = rhine.LoadRSAPrivateKeyPEM(keyPath)
		if err != nil {
			return err
		}
	case "Ed25519":
		var err error
		privKey, err = rhine.LoadPrivateKeyEd25519(keyPath)
		if err != nil {
			return err
		}
	}
	certbytes, err := rhine.CreateSelfSignedCertCA(privKey.Public(), privKey)
	if err != nil {
		return err
	}
	err = rhine.StoreCertificatePEM(certPath, certbytes)
	if err != nil {
		return err
	}

	return nil
}
