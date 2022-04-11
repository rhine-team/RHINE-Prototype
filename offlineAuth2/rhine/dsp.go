package rhine

import (
	"bytes"
	"encoding/gob"
	"time"
)

type T struct {
	time.Time
}

type Dsp struct {
	dsum  DSum
	epoch T
	sig   RhineSig
}

type toSignDsp struct {
	dsum  DSum
	epoch T
}

func (dsp Dsp) Sign(priv interface{}) error {

	var message bytes.Buffer
	enc := gob.NewEncoder(&message)

	err := enc.Encode(toSignDsp{
		dsum:  dsp.dsum,
		epoch: dsp.epoch,
	})

	if err != nil {
		return err
	}

	dsp.sig = RhineSig{
		Data: message.Bytes(),
	}

	err = dsp.sig.Sign(priv)
	if err != nil {
		return err
	}

	return nil
}
