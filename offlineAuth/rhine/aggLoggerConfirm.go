package rhine

import (
	"bytes"
	"crypto/sha256"
	"log"
)

type Confirm struct {
	Rsig         *RhineSig
	NdsHashBytes []byte
	Dsum         DSum
	EntityName   string

	// AggOrLog = 0 marks a AggConfirm
	// AggOrLog = 1 marks a LogConfirm
	AggOrLog int
}

func CreateConfirm(aggOrLog int, nds *Nds, entName string, dsu DSum, privkey interface{}) (*Confirm, error) {
	hasher := sha256.New()

	// It is a Agg confirm, so add Nds hash
	var err error
	var byt []byte
	byt = []byte{}

	if aggOrLog == 0 {
		byt, err = nds.NdsToSignBytes()
		if err != nil {
			log.Println("Nds to byte conversion failed.")
			return nil, err
		}

		hasher.Write(byt)
	}
	hasher.Write([]byte(entName))

	// Ready DSum for signing
	dsumByt, errDs := dsu.GetDSumToBytes()
	if errDs != nil {
		return nil, errDs
	}
	hasher.Write(dsumByt)

	res := &RhineSig{
		Data: hasher.Sum(nil),
	}

	if err := res.Sign(privkey); err != nil {
		return nil, err
	}

	//log.Printf("Pubkey of signing key: %+v \n Data %+v, ", privkey.(ed25519.PrivateKey).Public(), res.Data)

	confi := &Confirm{
		Rsig:         res,
		NdsHashBytes: byt,
		Dsum:         dsu,
		EntityName:   entName,
	}
	return confi, nil
}

func (c *Confirm) VerifyConfirm(pubKey any) bool {
	// Verify signature
	if !c.Rsig.Verify(pubKey) {
		//log.Printf("Pubkey used  %+v\n Data %+v\n", pubKey, l.Rsig.Data)
		log.Println("Verification of Confirm failed, signature did not match")
		return false
	}

	// Verify that signed content is actually what the Lwit contains
	hasher := sha256.New()

	// It is a Agg confirm, so add Nds hash

	if c.AggOrLog == 0 {
		hasher.Write(c.NdsHashBytes)
	}
	hasher.Write([]byte(c.EntityName))

	// Ready DSum for signing
	dsumByt, errDs := c.Dsum.GetDSumToBytes()
	if errDs != nil {
		return false
	}
	hasher.Write(dsumByt)

	resData := hasher.Sum(nil)

	if bytes.Compare(resData, c.Rsig.Data) != 0 {
		log.Println("Signed data not matching with Confirm content")
		return false
	}

	//log.Println("Confirm fully validated!")
	return true
}

func VerifyAggConfirmSlice(clist []Confirm, aggMap map[string]Agg) bool {
	res := true
	for _, lc := range clist {
		// TODO: Check existence in map
		res = res && lc.VerifyConfirm(aggMap[lc.EntityName].Pubkey)
	}
	if !res {
		log.Println("Confirm slice verification failed!")
	}
	return res
}

func VerifyLogConfirmSlice(clist []Confirm, logMap map[string]Log) bool {
	res := true
	for _, lc := range clist {
		// TODO: Check existence in map
		res = res && lc.VerifyConfirm(logMap[lc.EntityName].Pubkey)
	}
	if !res {
		log.Println("Confirm slice verification failed!")
	}
	return res
}

func (c *Confirm) ConfirmToTransportBytes() ([]byte, error) {
	byt, err := SerializeCBOR(*c)
	if err != nil {
		log.Println("FAILED Serializing Confirm", err)
		return []byte{}, err
	}
	return byt, nil
}

func TransportBytesToConfirm(byt []byte) (*Confirm, error) {
	res := &Confirm{}
	err := DeserializeCBOR(byt, res)
	if err != nil {
		log.Println("FAILED Deserializing Confirm ", err)
		return nil, nil
	}
	return res, nil
}
