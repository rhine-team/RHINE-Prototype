package rhine

import (
	"bytes"
	"encoding/gob"
	"time"
)

type Nds struct {
	nds       ndsToSign
	signednds RhineSig
}

type ndsToSign struct {
	log     Log
	zone    ZoneOwner
	al      AuthorityLevel
	tbsCert []byte
	exp     time.Time
}

func (n Nds) Sign(priv any) error {

	var message bytes.Buffer
	enc := gob.NewEncoder(&message)

	err := enc.Encode(n.nds)

	if err != nil {
		return err
	}

	n.signednds = RhineSig{
		Data: message.Bytes(),
	}

	err = n.signednds.Sign(priv)
	if err != nil {
		return err
	}

	return nil
}