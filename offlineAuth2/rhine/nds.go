package rhine

import (
	"bytes"
	"encoding/gob"
	"time"
)

type Nds struct {
	Nds       NdsToSign
	Signednds RhineSig
}

type NdsToSign struct {
	Log     []Log
	Agg     []Agg
	Zone    ZoneOwner
	Al      AuthorityLevel
	TbsCert []byte
	Exp     time.Time
}

func (n *Nds) Sign(priv interface{}) error {

	var message bytes.Buffer
	enc := gob.NewEncoder(&message)

	err := enc.Encode(n.Nds)

	if err != nil {
		return err
	}

	n.Signednds = RhineSig{
		Data: message.Bytes(),
	}

	err = n.Signednds.Sign(priv)
	if err != nil {
		return err
	}

	return nil
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
