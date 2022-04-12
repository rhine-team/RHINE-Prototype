package rhine

import (
	"bytes"
	"encoding/gob"
)

// Delegation Status proof:
// sig contains signature over DSum and T
// proof is merkle path as PoA or PoP

type Dsp struct {
	dsum   DSum
	epochT uint64
	sig    RhineSig
	proof  MPathProof
}

type toSignDsp struct {
	dsum   DSum
	epochT uint64
}

func (dsp Dsp) Sign(priv interface{}) error {

	var message bytes.Buffer
	enc := gob.NewEncoder(&message)

	err := enc.Encode(toSignDsp{
		dsum:   dsp.dsum,
		epochT: dsp.epochT,
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
