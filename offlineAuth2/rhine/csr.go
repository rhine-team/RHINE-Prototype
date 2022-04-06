package rhine

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"
)

// csr object holds additional rhine-related info, which will be added as extension to actual x509 csr
type Csr struct {
	zone      ZoneOwner
	ca        Authority
	log       Log
	al        AuthorityLevel
	exp       time.Time
	csr       x509.CertificateRequest
	signedcsr []byte
}

func (csr Csr) Sign(priv any) error {
	ext, err := csr.CreateCSRExtension()
	if err != nil {
		return err
	}

	csr.csr = x509.CertificateRequest{
		PublicKey: csr.zone.Pubkey.Public(),
		Subject: pkix.Name{
			CommonName: "RHINE_ZONE_OWNER:" + csr.zone.Name,
		},
		Extensions: []pkix.Extension{ext},
		DNSNames:   []string{csr.zone.Name},
	}

	csr.signedcsr, err = x509.CreateCertificateRequest(rand.Reader, &csr.csr, priv)
	if err != nil {
		return err
	}

	return nil

}

var (
	CsrExtOID = asn1.ObjectIdentifier{1, 3, 500, 9}
)

type CsrExt struct {
	zone ZoneOwner
	al   AuthorityLevel
	exp  time.Time
}

func (csr Csr) CreateCSRExtension() (pkix.Extension, error) {
	data, err := asn1.Marshal(CsrExt{
		zone: csr.zone,
		al:   csr.al,
		exp:  csr.exp,
	})
	if err != nil {
		return pkix.Extension{}, err
	}
	ext := pkix.Extension{
		Id:       CsrExtOID,
		Critical: true,
		Value:    data,
	}

	return ext, nil
}

func FindCSRExt(exts []pkix.Extension) (CsrExt, error) {
	if len(exts) == 0 {
		return CsrExt{}, errors.New("No CsrExt to parse")
	}

	var csrExt *pkix.Extension

	for _, ext := range exts {
		if ext.Id.Equal(CsrExtOID) {
			csrExt = &ext
		}
	}

	if csrExt == nil {
		return CsrExt{}, errors.New("ext OID is not CsrExt")
	}
	var Csrext CsrExt
	_, err := asn1.Unmarshal(csrExt.Value, &Csrext)
	if err != nil {
		return CsrExt{}, err
	}
	return Csrext, nil
}

func VerifyCSR(csr []byte) (*Csr, error) {
	var csrRequest *x509.CertificateRequest
	csrRequest, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}

	if err := csrRequest.CheckSignature(); err != nil {
		return nil, err
	}

	var csrExt CsrExt
	csrExt, err = FindCSRExt(csrRequest.Extensions)
	if err != nil {
		return nil, err
	}

	return &Csr{
		zone:      csrExt.zone,
		al:        csrExt.al,
		exp:       csrExt.exp,
		csr:       *csrRequest,
		signedcsr: csr,
	}, nil

}
