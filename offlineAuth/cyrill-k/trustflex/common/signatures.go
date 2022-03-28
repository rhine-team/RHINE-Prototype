// This files contains some helper definitions and functions
// to deal with signatures.

package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"github.com/google/certificate-transparency-go/tls"
	"log"
	"math/big"
)

type Signature tls.DigitallySigned

type Sig struct {
	R, S *big.Int
}

func (s *Sig) Convert(algo tls.SignatureAlgorithm, hashAlgorithm tls.HashAlgorithm) (Signature, error) {
	var ds tls.DigitallySigned
	var err error
	ds.Signature, err = asn1.Marshal(*s)

	if err != nil {
		return Signature(ds), fmt.Errorf("failed to marshal the signature: %s", err)
	}

	ds.Algorithm.Hash = hashAlgorithm
	ds.Algorithm.Signature = algo
	return Signature(ds), nil
}

func ConvertBack(signature Signature) (Sig, error) {
	var sig Sig
	rest, err := asn1.Unmarshal(signature.Signature, &sig)

	if err != nil {
		return sig, fmt.Errorf("failed to unmarshal the signature: %s", err)
	}

	if len(rest) > 0 {
		return sig, fmt.Errorf("%d data found after signature", len(rest))
	}

	return sig, nil
}

func TLSToCryptoHash(hashAlgorithm tls.HashAlgorithm) crypto.Hash {
	switch hashAlgorithm {
	case tls.MD5:
		return crypto.MD5
	case tls.SHA1:
		return crypto.SHA1
	case tls.SHA224:
		return crypto.SHA224
	case tls.SHA256:
		return crypto.SHA256
	case tls.SHA384:
		return crypto.SHA384
	case tls.SHA512:
		return crypto.SHA512
	default:
		return 0
	}
}

func StringToTLSHash(hashAlgo string) tls.HashAlgorithm{
	switch hashAlgo {

	case "MD5":
		return tls.MD5
	case "SHA1":
		return tls.SHA1
	case "SHA224":
		return tls.SHA224
	case "SHA256":
		return tls.SHA256
	case "SHA384":
		return tls.SHA384
	case "SHA512":
		return tls.SHA512
	default:
		log.Fatalf("%s is not a supported hash algorithm", hashAlgo)
		return tls.None
	}
}

func LoadPrivateKey(keyFile, sigAlgo string) interface{} {
	bytePrivateKey, err := KeyFromPEM(keyFile)
	LogError("Failed to read private key from file: %s", err)

	switch sigAlgo {
	case "RSA":
		privateKey, err := x509.ParsePKCS1PrivateKey(bytePrivateKey)
		LogError("Failed to parse RSA private key: %s", err)
		return *privateKey
	case "ECDSA":
		privateKey, err := x509.ParseECPrivateKey(bytePrivateKey)
		LogError("Failed to parse ECDSA private key: %s", err)
		return *privateKey

	default:
		log.Fatalf("%s is not a supported signature algorithm", sigAlgo)
		return nil
	}
}

func ComputeHash(algo tls.HashAlgorithm, data []byte) ([]byte, crypto.Hash, error) {
	hashType := TLSToCryptoHash(algo)

	if hashType == 0 {
		return nil, hashType, fmt.Errorf("specified algorithm is not supported: %v", algo)
	}

	hasher := hashType.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, hashType, fmt.Errorf("failed to compute hash of data: %v", err)
	}
	return hasher.Sum([]byte{}), hashType, nil
}

func VerifySignatures(eecert []*x509.Certificate, data []byte, signature Signature) error {
	var err error
	for idx, cert := range eecert {
		err = tls.VerifySignature(cert.PublicKey, data, tls.DigitallySigned(signature))
		if err != nil {
			return fmt.Errorf("signature %d verification failed", idx)
		}
	}
	return nil
}

// This is a separated method used to compute the signature of the updated root in BFT.
// Re-implemented since tls.VerifySignature() also compute the hash, which we already have
// since it is provided by Trillian when retrieving the latest root.
func (s *Signature) VerifySignature(pubKey crypto.PublicKey, data []byte) (bool, error) {
	algorithm := s.Algorithm.Signature
	switch algorithm {

	case tls.RSA:
		pubKey, ok := pubKey.(*rsa.PublicKey)

		if !ok {
			return false, fmt.Errorf("cannot use %T to verify signature", pubKey)
		}

		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, data, s.Signature); err != nil {
			return false, fmt.Errorf("signature verification failed: %s", err)
		}

		return true, nil

	case tls.ECDSA:
		pubKey, ok := pubKey.(*ecdsa.PublicKey)

		if !ok {
			return false, fmt.Errorf("cannot use %T to verify signature", pubKey)
		}

		sig, err := ConvertBack(*s)
		if err != nil {
			return false, fmt.Errorf("failed to convert signature: %s", err)
		}

		return ecdsa.Verify(pubKey, data, sig.R, sig.S), nil


	default:
		return false, fmt.Errorf("%T is not a valid or supported signature algoritm", algorithm)
	}
}

func Sign(privateKey crypto.PrivateKey, algorithm tls.HashAlgorithm, data interface{}) (tls.DigitallySigned, error) {
	byteData, err := json.Marshal(data)
	if err != nil {
		return tls.DigitallySigned{}, fmt.Errorf("failed to marhsal data: %s", err)
	}

	return tls.CreateSignature(privateKey, algorithm, byteData)
}

func Verify(publicKey crypto.PublicKey, data interface{}, signature Signature) error {
	byteData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marhsal data: %s", err)
	}

	return tls.VerifySignature(publicKey, byteData, tls.DigitallySigned(signature))
}
