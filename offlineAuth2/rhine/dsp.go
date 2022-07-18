package rhine

import (
	"bytes"
	"encoding/gob"
	"log"

	"github.com/google/certificate-transparency-go/x509"
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

	// TODO Change Away from GOB
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

func (dsp *Dsp) Verify(pub interface{}, zname string, rcertp *x509.Certificate, alC AuthorityLevel) bool {

	veri := dsp.Sig.Verify(pub)
	if !veri {
		log.Printf("The signature did not verify for the DSP: %+v", dsp)
		return false
	}

	// TODO Verify that data matches rsig data

	veriProof, err := (&dsp.Proof).VerifyMPathProof(dsp.Dsum.Dacc.Roothash, zname)
	if !veriProof || err != nil {
		log.Print("The Proof for DSP did not verify: %+v", dsp)
		return false
	}

	// Check if certificate in DSP matches PCert
	//TODO: ENABLE
	//bytes.Compare(dsp.Dsum.Cert, ExtractTbsRCAndHash(rcertp.RawTBSCertificate))

	// Check legal delegation
	//TODO: ENABLE
	//CheckLegalDelegationAuthority(alC, dsp.Dsum.Alv)

	// TODO more checks (time)
	return true
}
