package rhine

import (
	"bytes"
	"encoding/gob"
)

// Delegation Status proof:
// sig contains signature over DSum and T
// proof is merkle path as PoA or PoP

type Dsp struct {
	Dsum   DSum
	EpochT uint64
	Sig    RhineSig
	Proof  MPathProof
}

type toSignDsp struct {
	Dsum   DSum
	EpochT uint64
}

func (dsp *Dsp) Sign(priv interface{}) error {

	var message bytes.Buffer
	enc := gob.NewEncoder(&message)

	err := enc.Encode(toSignDsp{
		Dsum:   dsp.Dsum,
		EpochT: dsp.EpochT,
	})

	if err != nil {
		return err
	}

	dsp.Sig = RhineSig{
		Data: message.Bytes(),
	}

	err = dsp.Sig.Sign(priv)
	if err != nil {
		return err
	}

	return nil
}

func (dsp *Dsp) Verify(pub interface{}, zname string) bool {

	veri := dsp.Sig.Verify(pub)
	if !veri {
		return false
	}

	veriProof, err := (&dsp.Proof).VerifyMPathProof(dsp.Dsum.Dacc.Roothash, zname)
	if !veriProof || err != nil {
		return false
	}

	// TODO more checks
	return true
}
