package rhine

import (
	"crypto/x509"
	"errors"
)

type Psr struct {
	csr        *Csr
	psignedcsr RhineSig
	pcert      x509.Certificate
	dsp        *Dsp
}

func (psr Psr) Verify() error {
	// verify  csr
	// extract pzone
	// verify pcert
	// verify psignature on csr

	var err error
	psr.csr, err = VerifyCSR(psr.psignedcsr.Data)
	if err != nil {
		return err
	}

	pzone := GetParentZone(psr.csr.zone.Name)

	if _, err = psr.pcert.Verify(x509.VerifyOptions{
		DNSName: pzone,
	}); err != nil {
		return err
	}

	if ok := psr.psignedcsr.Verify(psr.pcert.PublicKey); !ok {
		return errors.New("rhinesig invalid")
	}

	return nil
}
