package rhine

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"log"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

// csr object holds additional rhine-related info, which will be added as extension to actual x509 csr
type Csr struct {
	Zone       ZoneOwner
	Ca         Authority
	Logs       []string
	Al         AuthorityLevel
	Exp        time.Time
	Csr        x509.CertificateRequest
	Revocation int
	Rid        []byte
	Signedcsr  []byte

	Pkey any
}

func (csr *Csr) Sign(priv any) error {
	ext, err := csr.CreateCSRExtension()
	if err != nil {
		return err
	}

	csr.Csr = x509.CertificateRequest{
		PublicKey: csr.Zone.Pubkey,
		Subject: pkix.Name{
			CommonName: "RHINE_ZONE_OWNER:" + csr.Zone.Name,
		},
		Extensions:      []pkix.Extension{ext},
		ExtraExtensions: []pkix.Extension{ext},
		DNSNames:        []string{csr.Zone.Name},
	}

	csr.Signedcsr, err = x509.CreateCertificateRequest(rand.Reader, &csr.Csr, priv)
	if err != nil {
		return err
	}

	//log.Printf("Csr. object at end of signing: %+v", csr)

	return nil

}

var (
	CsrExtOID = asn1.ObjectIdentifier{1, 3, 500, 9}
)

type CsrExt struct {
	Zone       ZoneOwner
	Al         int
	Exp        time.Time
	Revocation int
	CAuthority Authority
	Logs       []string
	Rid        []byte
}

func (csr *Csr) CreateCSRExtension() (pkix.Extension, error) {
	//log.Printf("Csr: %+v\n", *csr)
	if csr.Ca.Pubkey == nil {
		// TODO fix this workaround
		csr.Ca.Pubkey = []byte(nil)
	}
	data, err := asn1.Marshal(CsrExt{
		Zone:       csr.Zone,
		Al:         int(csr.Al), //TODO: Look at consq.
		Exp:        csr.Exp,
		Revocation: csr.Revocation,
		CAuthority: csr.Ca,
		Logs:       csr.Logs,
		Rid:        csr.Rid,
	})
	if err != nil {
		log.Println("Marshaling of extension failed!")
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

	// takes in a signed x509 certifiate request, parses it, checks signature, parses extension and returns as Csr object

	var csrRequest *x509.CertificateRequest
	csrRequest, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		log.Println("Could not parse csr:", err)
		return nil, err
	}

	if err := csrRequest.CheckSignature(); err != nil {
		log.Println("Signature check failed on CSR")
		return nil, err
	}

	var csrExt CsrExt
	csrExt, err = FindCSRExt(csrRequest.Extensions)
	if err != nil {
		log.Printf("Failed at finding Ext: %+v", csrRequest)
		return nil, err
	}

	return &Csr{
		Zone:       csrExt.Zone,
		Al:         AuthorityLevel(csrExt.Al),
		Exp:        csrExt.Exp,
		Revocation: csrExt.Revocation,
		Ca:         csrExt.CAuthority,
		Logs:       csrExt.Logs,
		Rid:        csrExt.Rid,
		Csr:        *csrRequest,
		Signedcsr:  csr,
		Pkey:       csrRequest.PublicKey,
	}, nil

}

func (csr *Csr) CheckAgainstCert(precert *x509.Certificate) bool {
	cs := csr.Csr
	res := cs.Subject.String() == precert.Subject.String() && EqualKeys(cs.PublicKey, precert.PublicKey)
	res = res && precert.DNSNames[0] == cs.DNSNames[0]
	return res
}

func (csr *Csr) ReturnRawBytes() []byte {
	return csr.Signedcsr
}

func (csr *Csr) ReturnRid() []byte {
	return csr.Rid
}

// Creates a rid given a csr
func (csr *Csr) createRID() ([]byte, error) {
	hasher := sha256.New()

	// t0
	if timeBinary, err := time.Now().MarshalBinary(); err != nil {
		return nil, err
	} else {
		hasher.Write(timeBinary)
	}

	// ZN
	hasher.Write([]byte(csr.Zone.Name))

	// pk
	if keyBytes, _, err := EncodePublicKey(csr.Zone.Pubkey); err != nil {
		return nil, err
	} else {
		hasher.Write(keyBytes)
	}

	// al
	hasher.Write([]byte{byte(csr.Al)})

	// expiration time
	if timeBinary, err := csr.Exp.MarshalBinary(); err != nil {
		return nil, err
	} else {
		hasher.Write(timeBinary)
	}

	// revocation bit
	hasher.Write([]byte{byte(csr.Revocation)})

	// A
	hasher.Write([]byte(csr.Ca.Name))

	// L
	for _, lo := range csr.Logs {
		hasher.Write([]byte(lo))
	}

	csr.Rid = hasher.Sum(nil)
	return csr.Rid, nil
}
