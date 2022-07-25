package rhine

import (
	"errors"
	"log"

	"github.com/google/certificate-transparency-go/x509"
)

type Psr struct {
	csr        *Csr
	psignedcsr RhineSig
	pcert      *x509.Certificate
	dsp        *Dsp

	ChildZone  string
	ParentZone string
}

// roots is a pool of trust roots to check the certi against
func (psr *Psr) Verify(roots *x509.CertPool) error {
	// verify  csr
	// extract pzone
	// verify pcert
	// verify psignature on csr

	var err error
	psr.csr, err = VerifyCSR(psr.psignedcsr.Data)
	if err != nil {
		log.Println("CSR verification failed")
		return err
	}

	pzone := GetParentZone(psr.csr.zone.Name)
	psr.ParentZone = pzone
	psr.ChildZone = psr.csr.zone.Name

	// Verify cert and names
	if err := CheckRCertNameAndValid(psr.pcert, pzone, roots); err != nil {
		return err
	}
	/*
		if _, err = psr.pcert.Verify(x509.VerifyOptions{
			DNSName: pzone,
			Roots:   roots,
		}); err != nil {
			log.Println("Wrong parent Cert/ Parent Name", err)
			log.Println("DSNNames then pzone: ", psr.pcert.DNSNames, pzone)
			log.Printf("Cert %+v", psr.pcert)
			return err
		}
	*/

	if ok := psr.psignedcsr.Verify(psr.pcert.PublicKey); !ok {
		log.Println("ACSR not valid!")
		return errors.New("Rhinesig invalid")
	}

	return nil
}

func (psr *Psr) GetZones() (string, string) {
	return GetParentZone(psr.csr.zone.Name), psr.csr.zone.Name
}

func (psr *Psr) GetRhineSig() RhineSig {
	return psr.psignedcsr
}

func (psr *Psr) GetAlFromCSR() AuthorityLevel {
	return psr.csr.al
}

func CheckRCertNameAndValid(pcert *x509.Certificate, pzone string, roots *x509.CertPool) error {
	if _, err := pcert.Verify(x509.VerifyOptions{
		DNSName: pzone,
		Roots:   roots,
	}); err != nil {
		log.Println("Wrong parent Cert/ Parent Name", err)
		log.Println("DSNNames then pzone: ", pcert.DNSNames, pzone)
		log.Printf("Cert %+v", pcert)
		return err
	}
	return nil
}

func CheckRCertValid(cert *x509.Certificate, roots *x509.CertPool) error {
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots: roots,
		// x509 doesnt know how to handle our extension
		// We disable it, since we just want validated the signature
		DisableCriticalExtensionChecks: true,
	}); err != nil {
		log.Println("Cert not validated to a trusted root", err)
		log.Printf("Cert %+v", cert)
		return err
	}
	return nil
}
