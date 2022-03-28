package common

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"
)

func StoreCertificateRequestPEM(path string, csr []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}

	pemcert := pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Headers: nil,
		Bytes:   csr,
	}

	err = pem.Encode(file, &pemcert)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

func LoadCertificateRequestPEM(path string) ([]byte, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)

	return block.Bytes, nil
}

func StoreCertificatePEM(path string, cert []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}

	pemcert := pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   cert,
	}

	err = pem.Encode(file, &pemcert)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

func LoadCertificatePEM(path string) (*x509.Certificate, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
func StorePrivateKeyEd25519(path string, key ed25519.PrivateKey) error {
	file, err := os.Create(path)
	if err != nil {
		log.Println(err)
	}

	privKey := pem.Block{
		Type:    "RAINS Ed25519 PRIVATE KEY",
		Headers: nil,
		Bytes:   key,
	}

	err = pem.Encode(file, &privKey)
	if err != nil {
		log.Println(err)
	}
	file.Close()
	return nil
}

func LoadPrivateKeyEd25519(path string) (ed25519.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)

	privKey := block.Bytes
	if err != nil {
		return nil, err
	}

	return privKey, nil

}

func StoreRSAPrivateKeyPEM(key *rsa.PrivateKey, path string) error{
	file, err := os.Create(path)
	if err != nil {
		return err
	}

	privKey := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(file, &privKey)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

func LoadRSAPrivateKeyPEM(path string) (*rsa.PrivateKey, error) {

	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil

}

func PublicKeyToStringPEM(key interface{}) (string, error) {

	switch key.(type) {
	case *rsa.PublicKey:
		pubKey := pem.Block{
			Type:    "RSA PUBLIC KEY",
			Headers: nil,
			Bytes:   x509.MarshalPKCS1PublicKey(key.(*rsa.PublicKey)),
		}

		return string(pem.EncodeToMemory(&pubKey)), nil

	case *ed25519.PublicKey:
		bytes, err := x509.MarshalPKIXPublicKey(*key.(*ed25519.PublicKey))
		if err != nil {
			fmt.Println(err)
		}
		pubKey := pem.Block{
			Type:    "PUBLIC KEY",
			Headers: nil,
			Bytes:   bytes,
		}

		return string(pem.EncodeToMemory(&pubKey)), nil

	default:
		return "", errors.New("unsupported key")
	}

}

func PublicKeyFromStringPEM(key string) (interface{}, error) {

	block, _ := pem.Decode([]byte(key))

	if block.Type == "RSA PUBLIC KEY" {
		pubKey, _ := x509.ParsePKCS1PublicKey(block.Bytes)
		return pubKey, nil

	} else if block.Type == "PUBLIC KEY" {
		pubKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
		return pubKey, nil

	} else {
		return nil, errors.New("unsupported key")
	}

}

func EncodePublicKey(key interface{}) (string, string, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		keybytes := x509.MarshalPKCS1PublicKey(key.(*rsa.PublicKey))
		return EncodeBase64(keybytes), "RSA", nil

	case *ed25519.PublicKey:
		keybytes, err := x509.MarshalPKIXPublicKey(*key.(*ed25519.PublicKey))
		if err != nil {
			return "", "", err
		}
		return EncodeBase64(keybytes), "Ed25519", nil
	case ed25519.PublicKey:
		keybytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", "", err
		}
		return EncodeBase64(keybytes), "Ed25519", nil

	default:
		return "", "", errors.New("unsupported key")
	}
}

func DecodePublicKey(key string, alg string) (interface{}, error) {
	fmt.Println(key, alg)
	decodedKey, err := DecodeBase64(key)
	if err != nil {
		return nil, err
	}
	switch alg {
	case "RSA":
		pubKey, err := x509.ParsePKCS1PublicKey(decodedKey)
		if err != nil {
			return nil, err
		}
		return pubKey, nil

	case "Ed25519":
		pubKey, err := x509.ParsePKIXPublicKey(decodedKey)
		if err != nil {
			return nil, err
		}
		if _, ok := pubKey.(ed25519.PublicKey); ok {
			return pubKey.(ed25519.PublicKey), nil
		} else {
			return "", errors.New("public key type / alg type mismatch")
		}

	default:
		return "", errors.New("unsupported alg")
	}
}

func CreateSelfSignedCert(pubkey interface{}, privkey interface{}, domain string) ([]byte, error) {
	if _, ok := pubkey.(*ed25519.PublicKey); ok {
		pubkey = *pubkey.(*ed25519.PublicKey)
	}
	var req x509.Certificate
	req.DNSNames = append(req.DNSNames, domain)
	req.SerialNumber = big.NewInt(1)
	req.NotBefore = time.Now()
	req.NotAfter = time.Now().Add(time.Hour)
	certbytes, err := x509.CreateCertificate(rand.Reader, &req, &req, pubkey, privkey)
	if err != nil {
		log.Println("error creating self signed cert", err)
	}

	return certbytes, err
}

func CreateSelfSignedCertCA(pubkey interface{}, privkey interface{}) ([]byte, error) {
	if _, ok := pubkey.(*ed25519.PublicKey); ok {
		pubkey = *pubkey.(*ed25519.PublicKey)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RHINE EXAMPLE CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 356),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	certbytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubkey, privkey)
	if err != nil {
		log.Println("error creating self signed cert", err)
	}
	return certbytes, err
}

func EncodeBase64(bytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func DecodeBase64(data string) ([]byte, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(data)
	return bytes, err
}

func GetParentZone(subzone string) string {
	split := strings.SplitN(subzone, ".", 2)
	if len(split) > 1 {
		return split[1]
	} else {
		return ""
	}

}

