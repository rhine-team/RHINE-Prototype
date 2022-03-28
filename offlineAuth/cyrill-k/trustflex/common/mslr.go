// Definitions related to a Multi-Signed Log Root

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

type MultiSignedLogRoot struct {
	Root *types.LogRootV1
	Signatures map[string]Signature
}

func NewMSLR(root *types.LogRootV1) *MultiSignedLogRoot {
	mslr := &MultiSignedLogRoot{Root: root}
	mslr.Signatures = make(map[string]Signature)
	return mslr
}

func (mslr *MultiSignedLogRoot) Sign(id string, privKey crypto.PrivateKey, hashAlgorithm tls.HashAlgorithm) error {

	var err error
	var ds tls.DigitallySigned

	switch privKey := privKey.(type) {

	case ecdsa.PrivateKey:
		var sig Sig
		sig.R, sig.S, err = ecdsa.Sign(rand.Reader, &privKey, mslr.Root.RootHash)
		if err != nil {
			return fmt.Errorf("failed to sign MSLR: %s", err)
		}

		signature, err := sig.Convert(tls.ECDSA, hashAlgorithm)
		if err != nil {
			return fmt.Errorf("could not convert ECDSA signature: %s", err)
		}
		log.Printf("Signature algorithm: %v", signature.Algorithm)
		mslr.Signatures[id] = signature
		return nil

	case rsa.PrivateKey:
		ds.Signature, err = rsa.SignPKCS1v15(rand.Reader, &privKey, crypto.SHA256, mslr.Root.RootHash)
		ds.Algorithm.Hash = hashAlgorithm
		ds.Algorithm.Signature = tls.RSA
		mslr.Signatures[id] = Signature(ds)
		return nil

	default:
		return fmt.Errorf("%T private key is not supported", privKey)
	}

}

func (mslr *MultiSignedLogRoot) Verify(validID string, pubKeys map[string]crypto.PublicKey) (bool, error) {
	rootHash := mslr.Root.RootHash
	signature := mslr.Signatures[validID] // assume all signatures are using the same algorithm
	algorithm := signature.Algorithm.Signature
	var err error
	var sig Sig

	switch algorithm {

	case tls.RSA:
		for idx, sig := range mslr.Signatures {
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
		for idx, sign := range mslr.Signatures {
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
		return false, fmt.Errorf("%s is not a supported algorithm type", algorithm)

	}

}

func (mslr *MultiSignedLogRoot) Publish(id string) error {
	jsonMSLR, err := json.Marshal(mslr)
	if err != nil {
		return err
	}

	id = strings.ReplaceAll(id, "/", "")
	err = ioutil.WriteFile("trillian/mslr-"+strings.ReplaceAll(id, "/", ""), jsonMSLR, 0644)
	if err != nil {
		return err
	}

	return nil
}