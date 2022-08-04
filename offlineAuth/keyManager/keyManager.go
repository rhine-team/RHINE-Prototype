package keyManager

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"

	"fmt"
	"strings"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
)

// These functions are from the old offlineAuth version

func CreateRSAKey(path string, pubkey bool) error {
	PrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	pbkey := PrivateKey.Public().(*rsa.PublicKey)

	if err != nil {
		return err
	}

	if pubkey {
		pa := strings.ReplaceAll(path, ".pem", "")
		err = rhine.StoreRSAPublicKeyPEM(pbkey, pa+"_pub.pem")

		if err != nil {
			return err
		}
	}

	err = rhine.StoreRSAPrivateKeyPEM(PrivateKey, path)
	if err != nil {
		return err
	}

	// Print hex-string DER
	fmt.Println("DER of key as hex string: ", rhine.PEMBytesToHexString(x509.MarshalPKCS1PrivateKey(PrivateKey)))

	return nil
}

func CreateEd25519Key(path string, pubkey bool) error {
	pbkey, privatekey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		return err
	}

	if pubkey {
		pa := strings.ReplaceAll(path, ".pem", "")

		err = rhine.StorePublicKeyEd25519(pa+"_pub.pem", pbkey)

		if err != nil {
			return err
		}
	}

	err = rhine.StorePrivateKeyEd25519(path, privatekey)
	if err != nil {
		return err
	}

	// Print hex-string DER
	fmt.Println("DER of private key as hex string: ", rhine.PEMBytesToHexString(privatekey))

	return nil
}

func DerivePubKeyRSA(privPath string, path string) error {
	// Read in private key
	PrivateKey, err := rhine.LoadRSAPrivateKeyPEM(privPath)
	if err != nil {
		return err
	}

	pbkey := PrivateKey.Public().(*rsa.PublicKey)
	err = rhine.StoreRSAPublicKeyPEM(pbkey, path)
	if err != nil {
		return err
	}
	return nil
}

func DerivePubKeyEd25519(privPath string, path string) error {
	// Read in private key
	PrivateKey, err := rhine.LoadPrivateKeyEd25519(privPath)
	if err != nil {
		return err
	}

	pbkey := PrivateKey.Public().(ed25519.PublicKey)
	err = rhine.StorePublicKeyEd25519(path, pbkey)
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

func CreateCertificateSignedByCA(alg string, keyPath string, caKeyPath string, pathCACert string, certPath string, name string) error {
	var privKey crypto.Signer
	var errCA error
	var privKeyCA crypto.Signer
	switch alg {
	case "RSA":
		var err error
		privKey, err = rhine.LoadRSAPrivateKeyPEM(keyPath)
		privKeyCA, errCA = rhine.LoadRSAPrivateKeyPEM(caKeyPath)
		if err != nil {
			return err
		}
		if errCA != nil {
			return errCA
		}
	case "Ed25519":
		var err error
		privKey, err = rhine.LoadPrivateKeyEd25519(keyPath)
		privKeyCA, errCA = rhine.LoadPrivateKeyEd25519(caKeyPath)
		if err != nil {
			return err
		}
		if errCA != nil {
			return errCA
		}
	}
	certbytes, err := rhine.CreateCertificateUsingCA(privKey.Public(), privKey, privKeyCA, pathCACert, name)
	if err != nil {
		return err
	}
	err = rhine.StoreCertificatePEM(certPath, certbytes)
	if err != nil {
		return err
	}

	return nil
}
