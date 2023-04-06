package rhine

import (
	//"bytes"
	//"crypto/sha256"

	"errors"
	//"log"
	//"reflect"
	//"time"
	//"github.com/google/certificate-transparency-go/x509"
)

type Prl struct {
	Psr       *Psr
	Precert   []byte
	Signature []byte
}

func (p *Prl) PrlToBytes() ([]byte, error) {
	bytes, err := SerializeCBOR(p)
	return bytes, err
}

func PrlFromBytes(in []byte) (*Prl, error) {
	prl := &Prl{}
	err := DeserializeCBOR(in, prl)
	return prl, err
}

func (p *Prl) SignPrl(privkey any) error {
	p.Signature = nil
	byt, err := p.PrlToBytes()
	if err != nil {
		return err
	}
	rsig := RhineSig{
		Data: byt,
	}
	err = rsig.Sign(privkey)
	if err != nil {
		return err
	}
	p.Signature = rsig.Signature

	return nil
}

func (p *Prl) VerifyPrl(pubkey any) error {
	rsig := RhineSig{
		Signature: p.Signature,
	}
	p.Signature = nil
	byt, err := p.PrlToBytes()
	if err != nil {
		return err
	}
	rsig.Data = byt

	boolv := rsig.Verify(pubkey)

	if !boolv {
		return errors.New("PRL has no valid signature")
	}
	return nil
}
