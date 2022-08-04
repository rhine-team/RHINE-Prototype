package rhine

import (
	"bytes"
	"crypto/sha256"
	"log"
)

type Lwit struct {
	Rsig     *RhineSig
	NdsBytes []byte
	Log      *Log
	LogList  []string
}

func CreateLwit(nds *Nds, loge *Log, loglist []string, privkey interface{}) (*Lwit, error) {
	hasher := sha256.New()
	byt, err := nds.NdsToSignBytes()
	if err != nil {
		log.Println("Nds to byte conversion failed.")
		return nil, err
	}

	hasher.Write(byt)
	hasher.Write([]byte(loge.Name))
	// Write all designated log names
	for _, l := range loglist {
		hasher.Write([]byte(l))
	}

	res := &RhineSig{
		Data: hasher.Sum(nil),
	}

	if err := res.Sign(privkey); err != nil {
		return nil, err
	}

	//log.Printf("Pubkey of signing key: %+v \n Data %+v, ", privkey.(ed25519.PrivateKey).Public(), res.Data)

	lwi := &Lwit{
		Rsig:     res,
		NdsBytes: byt,
		Log:      loge,
		LogList:  loglist,
	}
	return lwi, nil
}

func (l *Lwit) VerifyLwit(pubKey any) bool {
	// Verify signature
	if !l.Rsig.Verify(pubKey) {
		//log.Printf("Pubkey used  %+v\n Data %+v\n", pubKey, l.Rsig.Data)
		log.Println("Verification of Lwit failed, signature did not match")
		return false
	}

	// Verify that signed content is actually what the Lwit contains
	hasher := sha256.New()

	hasher.Write(l.NdsBytes)
	hasher.Write([]byte(l.Log.Name))
	// Write all designated log names
	for _, lo := range l.LogList {
		hasher.Write([]byte(lo))
	}
	resData := hasher.Sum(nil)

	if bytes.Compare(resData, l.Rsig.Data) != 0 {
		log.Println("Signed data not matching with Log Witness content")
		return false
	}

	log.Println("Log witness fully validated!")
	return true
}

func VerifyLwitSlice(lwitlist []Lwit, logMap map[string]Log) bool {
	res := true
	for _, lw := range lwitlist {
		// TODO: Check existence in map
		res = res && lw.VerifyLwit(logMap[lw.Log.Name].Pubkey)
	}
	if !res {
		log.Println("LogWit slice verification failed!")
	}
	return res
}
