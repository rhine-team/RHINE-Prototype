package rhine

import (
	"bytes"
	"crypto/sha256"

	//"encoding/gob"
	"errors"
	"log"
	"reflect"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

type Nds struct {
	Nds       NdsToSign
	Signednds RhineSig
}

type NdsToSign struct {
	Log     []string
	Agg     []string
	Zone    ZoneOwner
	Al      AuthorityLevel
	TbsCert []byte
	Exp     time.Time
}

func (n *Nds) Sign(priv interface{}) error {

	/*
			var message bytes.Buffer
			enc := gob.NewEncoder(&message)

			err := enc.Encode(n.Nds)

			if err != nil {
				return err
			}



		n.Signednds = RhineSig{
			Data: message.Bytes(),
		}
	*/

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

func (n *Nds) VerifyNDS(pubKey any) error {
	/*
		var message bytes.Buffer
		enc := gob.NewEncoder(&message)
		err := enc.Encode(n.Nds)

		if err != nil {
			return err
		}
		encNDS := message.Bytes()
	*/
	encNDS, err := n.NdsToSignBytes()
	if err != nil {
		return err
	}

	// Check that rhinesig data matches NDS data
	if bytes.Compare(encNDS, n.Signednds.Data) != 0 {
		/*
			ands, _ := DeserializeStructure[NdsToSign](encNDS)
			bnds, _ := DeserializeStructure[NdsToSign](n.Signednds.Data)
			log.Printf("Our freshly encoded nds %+v \n Decoded nds from message %+v ", ands, bnds)
			//log.Printf("\n Bytes we computed %+v \n Bytes from the data %+v", message.Bytes(), n.Signednds.Data)
			//log.Printf("Result of compare: ", bytes.Compare(encNDS, n.Signednds.Data))
		*/
		return errors.New("Signed data not matching with NDS content")
	}

	// Verify Signature
	if !n.Signednds.Verify(pubKey) {
		log.Printf("Signature on NDS not matching! %+v: ", n.Nds)
		return errors.New("Signature on NDS not by correct key-pair")
	}

	return nil
}

// Check if NDS and CSR match
func (n *Nds) CheckAgainstCSR(csr *Csr) bool {
	// Check logs
	matching := reflect.DeepEqual(n.Nds.Log, csr.logs)
	// Check zone
	matching = matching && n.Nds.Zone.Name == csr.zone.Name
	// Check Al
	matching = matching && n.Nds.Al == csr.al
	// TODO more stuff?

	return matching
}

// Matches Lwits against a NDS
// NOTE: Never use gob encoding to make bytes comparable across systems!
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

// This function is used to gen bytes for signing
func (n *Nds) NdsToSignBytes() ([]byte, error) {
	hasher := sha256.New()

	for _, l := range n.Nds.Log {
		hasher.Write([]byte(l))
	}

	for _, a := range n.Nds.Agg {
		hasher.Write([]byte(a))
	}

	hasher.Write([]byte(n.Nds.Zone.Name))
	hasher.Write([]byte{byte(n.Nds.Al)})
	hasher.Write(n.Nds.TbsCert)

	// expiration time
	if timeBinary, err := n.Nds.Exp.MarshalBinary(); err != nil {
		return nil, err
	} else {
		hasher.Write(timeBinary)
	}

	return hasher.Sum(nil), nil
}

func (n *Nds) NdsToBytes() ([]byte, error) {
	byt, err := SerializeStructure[Nds](*n)
	if err != nil {
		return []byte{}, err
	}
	return byt, nil
}

func BytesToNds(byt []byte) (*Nds, error) {
	nds, err := DeserializeStructure[Nds](byt)
	if err != nil {
		return nil, nil
	}
	return &nds, nil
}

func ExtractTbsRCAndHash(cert *x509.Certificate) []byte {
	hasher := sha256.New()
	//log.Println("TBS looks like this: ", cert.RawTBSCertificate)
	hasher.Write(cert.RawTBSCertificate)
	return hasher.Sum(nil)
}
