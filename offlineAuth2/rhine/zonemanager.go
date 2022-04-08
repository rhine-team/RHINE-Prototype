package rhine

import (
	"errors"
	"github.com/google/certificate-transparency-go/x509"
	"time"
)

// zone manager manages zone, can act as parent or child zone

type ZoneManager struct {
	zone    ZoneOwner
	privkey any
	rcert   *x509.Certificate
}

// create csr

func (zm ZoneManager) CreateSignedCSR(authlevel AuthorityLevel, exp time.Time, ca Authority, log Log) (*Csr, error) {
	csr := Csr{
		zone: zm.zone,
		ca:   ca,
		log:  log,
		al:   authlevel,
		exp:  exp,
	}

	if err := csr.Sign(zm.privkey); err != nil {
		return nil, err
	}

	return &csr, nil

}

func (zm ZoneManager) VerifyChildCSR(rawcsr []byte) (*Csr, error) {
	// checks if csr signature ok
	csr, err := VerifyCSR(rawcsr)
	if err != nil {
		return nil, err
	}

	// check if request for valid child zone
	if ok := GetParentZone(csr.zone.Name) == zm.zone.Name; !ok {
		return nil, errors.New("csr zone " + csr.zone.Name + " is not a child zone of " + zm.zone.Name)
	}

	//TODO check if delegation legal??

	return csr, nil
}

func (zm ZoneManager) CreatePSR(csr *Csr) *Psr {
	psr := Psr{
		csr:        csr,
		psignedcsr: RhineSig{},
		pcert:      *zm.rcert,
		dsp:        nil,
	}

	psr.psignedcsr.Data = csr.signedcsr
	psr.psignedcsr.Sign(zm.privkey)

	// dsp proof ret here?

	return &psr
}

// dsproofret

func (zm ZoneManager) DSProofRet(log Log, cz ZoneOwner, pz ZoneOwner) {

}
