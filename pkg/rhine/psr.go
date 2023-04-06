package rhine

import (
	"errors"
	"log"

	"github.com/google/certificate-transparency-go/x509"
)

type Psr struct {
	Csr        *Csr
	Psignedcsr RhineSig
	Pcert      *x509.Certificate
	Dsp        *Dsp

	ChildZone  string
	ParentZone string
}

func CreatePsr(pcert *x509.Certificate, rsig *RhineSig) *Psr {
	psr := Psr{
		Psignedcsr: *rsig,
		Pcert:      pcert,
	}
	return &psr
}

// roots is a pool of trust roots to check the certi against
func (psr *Psr) Verify(roots *x509.CertPool) error {
	// verify  csr
	// extract pzone
	// verify pcert
	// verify psignature on csr

	var err error
	psr.Csr, err = VerifyCSR(psr.Psignedcsr.Data)
	if err != nil {
		log.Println("CSR verification failed")
		return err
	}

	pzone := GetParentZone(psr.Csr.Zone.Name)
	psr.ParentZone = pzone
	psr.ChildZone = psr.Csr.Zone.Name

	// Verify cert and names
	if err := CheckRCertNameAndValid(psr.Pcert, pzone, roots); err != nil {
		return err
	}

	if ok := psr.Psignedcsr.Verify(psr.Pcert.PublicKey); !ok {
		log.Println("ACSR not valid!")
		return errors.New("Rhinesig invalid")
	}

	return nil
}

func (psr *Psr) GetZones() (string, string) {
	return GetParentZone(psr.Csr.Zone.Name), psr.Csr.Zone.Name
}

func (psr *Psr) GetRhineSig() RhineSig {
	return psr.Psignedcsr
}

func (psr *Psr) GetLogs() []string {
	return psr.Csr.Logs
}

func (psr *Psr) GetCsr() *Csr {
	return psr.Csr
}

func (psr *Psr) GetAlFromCSR() AuthorityLevel {
	return psr.Csr.Al
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
