package rhine

import (
	"crypto/sha256"
	"log"
)

type Lwit struct {
	Rsig *RhineSig
	Nds  *Nds
	Log  *Log
}

func CreateLwit(nds *Nds, loge *Log, privkey interface{}) (*Lwit, error) {
	hasher := sha256.New()
	byt, err := nds.NdsToBytes()
	if err != nil {
		log.Println("Nds to byte conversion failed.")
		return nil, err
	}

	hasher.Write(byt)
	hasher.Write([]byte(loge.Name))
	res := &RhineSig{
		Data: hasher.Sum(nil),
	}

	if err := res.Sign(privkey); err != nil {
		return nil, err
	}

	lwi := &Lwit{
		Rsig: res,
		Nds:  nds,
		Log:  loge,
	}
	return lwi, nil
}
