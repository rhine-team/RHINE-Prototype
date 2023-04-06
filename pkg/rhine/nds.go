package rhine

import (
	"bytes"
	"crypto/sha256"

	"errors"
	"log"

	"time"

	"github.com/google/certificate-transparency-go/x509"
)

type Nds struct {
	Nds       NdsToSign
	Signednds RhineSig
}

type NdsToSign struct {
	//Log     []string
	Agg     []string
	Zone    ZoneOwner
	Al      AuthorityLevel
	TbsCert []byte
	Exp     time.Time
}

func (n *Nds) Sign(priv interface{}) error {

	byt, err := n.NdsToSignBytes()
	if err != nil {
		return err
	}
	n.Signednds = RhineSig{
		Data: byt,
	}

	err = n.Signednds.Sign(priv)
	if err != nil {
		return err
	}

	return nil
}

// TODO: Check this function again (inconsistent after changes)
func (n *Nds) VerifyNDS(pubKey any) error {

	encNDS, err := n.NdsToSignBytes()
	if err != nil {
		return err
	}

	newRhineSig := &RhineSig{Data: encNDS, Signature: n.Signednds.Signature}

	// Verify Signature
	if !newRhineSig.Verify(pubKey) {
		log.Printf("Signature on NDS not matching! %+v: ", n.Nds)
		return errors.New("Signature on NDS not by correct key-pair")
	}

	return nil
}

// Check if NDS and CSR match
func (n *Nds) CheckAgainstCSR(csr *Csr) bool {
	// Check logs
	//matching := reflect.DeepEqual(n.Nds.Log, csr.logs)
	matching := true
	// Check zone
	matching = matching && n.Nds.Zone.Name == csr.Zone.Name
	// Check Al
	matching = matching && n.Nds.Al == csr.Al

	return matching
}

// Matches Lwits against a NDS
func (n *Nds) MatchWithLwits(lwitslist []Lwit) bool {
	res := true
	for _, lw := range lwitslist {
		ndsByt, _ := n.NdsToSignBytes()
		com := bytes.Compare(lw.NdsBytes, ndsByt) == 0
		if !com {
			//ands, _ := DeserializeStructure[Nds](lw.NdsBytes)
			//bnds, _ := DeserializeStructure[Nds](ndsByt)
			//log.Printf("Lwit NDS %v+\n NDS NDS %v+\n", ands, bnds)
			//log.Printf("LWit NDS %+v\n NDS NDS %+v \n %T \n %T", lw.NdsBytes, ndsByt, lw.NdsBytes, ndsByt)
			log.Println("Nds Bytes in log witness did not match")
		}
		res = res && com
	}
	return res
}

func (n *Nds) ConstructDSum() DSum {
	res := DSum{
		Dacc: DAcc{
			Zone:     n.Nds.Zone.Name,
			Roothash: []byte{}, // TODO Look at conseq. of this
		},
		Alv:  n.Nds.Al,
		Cert: n.Nds.TbsCert,
		Exp:  n.Nds.Exp,
	}
	return res
}

// Matches a slice of AggConfirms with an NDS
func (n *Nds) MatchWithConfirm(conf []Confirm) bool {
	sigBytes, err := n.NdsToSignBytes()
	if err != nil {
		return false
	}

	res := true
	for _, confi := range conf {
		// Check if hash of nds is the same
		// Only works for AggConfirm
		res = res && (confi.AggOrLog == 0 && bytes.Compare(sigBytes, confi.NdsHashBytes) == 0)
	}
	return res
}

func (n *Nds) NdsToSignBytes() ([]byte, error) {
	hasher := sha256.New()
	bytes, err := n.NdsToBytes()
	if err != nil {
		return []byte{}, err
	}
	return hasher.Sum(bytes), nil
}

func (n *Nds) NdsToBytes() ([]byte, error) {
	byt, err := SerializeCBOR(*n)
	if err != nil {
		log.Println("FAILED Serializing NDS", err)
		return []byte{}, err
	}
	return byt, nil
}

func BytesToNds(byt []byte) (*Nds, error) {
	//confirm, err := DeserializeStructure[Confirm](byt)
	res := &Nds{}
	err := DeserializeCBOR(byt, res)
	if err != nil {
		log.Println("FAILED Deserializing NDS ", err)
		return nil, nil
	}
	return res, nil
}

func ExtractTbsRCAndHash(cert *x509.Certificate, removeSCT bool) []byte {
	hasher := sha256.New()

	// Remove CT Poison if PreCert
	tbsbytes := cert.RawTBSCertificate
	if cert.IsPrecertificate() {
		tbsbytes, _ = x509.RemoveCTPoison(tbsbytes)
	}

	bytes, err := x509.RemoveSCTList(tbsbytes)
	if err != nil {
		// There was no SCT list
		bytes = tbsbytes
	}

	hasher.Write(bytes)
	return hasher.Sum(nil)
}
