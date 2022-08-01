package rhine

import (
	"bytes"
	//"crypto/sha256"
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
	data, err := dsp.Dsum.GetDSumToBytes()
	if err != nil {
		return err
	}
	data = append(data, []byte(string(dsp.EpochT))...)

	dsp.Sig = RhineSig{
		Data: data,
	}

	err = dsp.Sig.Sign(priv)
	if err != nil {
		return err
	}

	return nil
}

func (dsp *Dsp) Verify(pub interface{}, zname string, rcertp *x509.Certificate, alC AuthorityLevel) bool {

	// Serialize DSP
	data, err := dsp.Dsum.GetDSumToBytes()
	if err != nil {
		log.Println("Failed converting DSum to bytes")
		return false
	}
	data = append(data, []byte(string(dsp.EpochT))...)

	// Verify dsp signature
	newSig := RhineSig{
		Data:      data,
		Signature: dsp.Sig.Signature,
	}
	veri := newSig.Verify(pub)
	if !veri {
		log.Printf("The signature did not verify for the DSP: %+v", dsp)
		return false
	}

	// Verify inclusion / exclusion using Merkle Proof
	veriProof, err := (&dsp.Proof).VerifyMPathProof(dsp.Dsum.Dacc.Roothash, zname)
	if !veriProof || err != nil {
		log.Print("The Proof for DSP did not verify: %+v", dsp)
		return false
	}

	// Check if certificate in DSP matches PCert
	// TODO: ENABLE
	if false && bytes.Compare(dsp.Dsum.Cert, ExtractTbsRCAndHash(rcertp, false)) != 0 {
		log.Println("Cert in DSP does not match PCert")
		return false
	}

	// Check legal delegation
	if !CheckLegalDelegationAuthority(dsp.Dsum.Alv, alC) {
		return false
	}

	return true
}

/*
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
	if !CheckLegalDelegationAuthority(dsp.Dsum.Alv, alC) {
		return false
	}

	// TODO more checks (time)
	return true
}
*/
