// Definitions related to a Multi-Signed Map Root

package common

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/trillian/types"
	"io/ioutil"
	"log"
	"strings"
)

type MultiSignedMapRoot struct {
	Root *types.MapRootV1
	Signatures map[string]Signature
}

func NewMSMR(root *types.MapRootV1) *MultiSignedMapRoot {
	msmr := &MultiSignedMapRoot{Root: root}
	msmr.Signatures = make(map[string]Signature)
	return msmr
}

func (msmr *MultiSignedMapRoot) Sign(id string, privKey crypto.PrivateKey, hashAlgorithm tls.HashAlgorithm) error {

	var err error
	var ds tls.DigitallySigned

	switch privKey := privKey.(type) {

	case ecdsa.PrivateKey:
		var sig Sig
		sig.R, sig.S, err = ecdsa.Sign(rand.Reader, &privKey, msmr.Root.RootHash)
		if err != nil {
			return fmt.Errorf("failed to sign MSMR: %s", err)
		}

		signature, err := sig.Convert(tls.ECDSA, hashAlgorithm)
		if err != nil {
			return fmt.Errorf("could not convert ECDSA signature: %s", err)
		}
		log.Printf("Signature algorithm: %v", signature.Algorithm)
		msmr.Signatures[id] = signature
		return nil

	case rsa.PrivateKey:
		ds.Signature, err = rsa.SignPKCS1v15(rand.Reader, &privKey, crypto.SHA256, msmr.Root.RootHash)
		ds.Algorithm.Hash = hashAlgorithm
		ds.Algorithm.Signature = tls.RSA
		msmr.Signatures[id] = Signature(ds)
		return nil

	default:
		return fmt.Errorf("%T private key is not supported", privKey)
	}

}

func (msmr *MultiSignedMapRoot) Verify(validID string, pubKeys map[string]crypto.PublicKey) (bool, error) {
	rootHash := msmr.Root.RootHash
	signature := msmr.Signatures[validID]
	algorithm := signature.Algorithm.Signature
	var err error
	var sig Sig

	switch algorithm {

	case tls.RSA:
		for idx, sig := range msmr.Signatures {
			pubKey, ok := pubKeys[idx].(*rsa.PublicKey)

			if !ok {
				return false, fmt.Errorf("cannot verify %s signature with %T", idx, pubKey)
			}

			if err := rsa.VerifyPKCS1v15(pubKey, TLSToCryptoHash(signature.Algorithm.Hash), rootHash, sig.Signature); err != nil {
				return false, fmt.Errorf("signature verification %s failed: %s", idx, err)
			}
		}

		return true, nil

	case tls.ECDSA:
		for idx, sign := range msmr.Signatures {
			pubKey, ok := pubKeys[idx].(*ecdsa.PublicKey)

			if !ok {
				return false, fmt.Errorf("cannot verify %s signature with %T", idx, pubKey)
			}

			sig, err = ConvertBack(sign)
			if err != nil {
				return false, fmt.Errorf("failed to convert signature %s: %s", idx, err)
			}

			if !ecdsa.Verify(pubKey, rootHash, sig.R, sig.S) {
				return false, fmt.Errorf("signature verification %s failed", idx)
			}
		}

		return true, nil

	default:
		return false, fmt.Errorf("%d is not a supported algorithm type", algorithm)

	}

}

// Publish is used at the end of the Signing phase,
// and writes the MSMR to a file
func (msmr *MultiSignedMapRoot) Publish(id string) error {
	jsonMSMR, err := json.Marshal(msmr)
	if err != nil {
		return err
	}

	id = strings.ReplaceAll(id, "/", "")
	err = ioutil.WriteFile("trillian/msmr-"+strings.ReplaceAll(id, "/", ""), jsonMSMR, 0644)
	if err != nil {
		return err
	}

	return nil
}