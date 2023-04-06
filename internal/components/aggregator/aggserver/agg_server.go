package aggserver

import (
	//"bytes"
	"context"
	"errors"

	//"fmt"
	"log"
	//"os"
	//"sync"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/internal/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/internal/components/aggregator"
	"github.com/rhine-team/RHINE-Prototype/pkg/rhine"
)

/*
var ft1 *os.File
var measureT = false
var timeout = time.Scond * 7200
var startTime time.Time
var started int
*/

var timeout = time.Second * 7200
var startTime time.Time
var started int

type AggServer struct {
	pf.UnimplementedAggServiceServer
	AggManager *rhine.AggManager
}

func (s *AggServer) DSRetrieval(ctx context.Context, in *pf.RetrieveDSALogRequest) (*pf.RetrieveDSALogResponse, error) {
	res := &pf.RetrieveDSALogResponse{}

	dsaBytes, dsaSigs, err := s.AggManager.Dsalog.DSRetrieve(in.RequestedZones, s.AggManager.GetPrivKey(), s.AggManager.DB)
	if err != nil {
		return res, err
	}

	res = &pf.RetrieveDSALogResponse{
		DSAPayload:    dsaBytes,
		DSASignatures: dsaSigs,
	}
	return res, nil

}

func (s *AggServer) DSProofRet(ctx context.Context, in *pf.DSProofRetRequest) (*pf.DSProofRetResponse, error) {
	res := &pf.DSProofRetResponse{}

	log.Printf("Received a DSProofRet request: %+v", in)

	dsp, dsperr := s.AggManager.DSProof(in.Parentzone, in.Childzone)
	if dsperr != nil {
		return res, dsperr
	}

	// Encode and send
	//dspseri, err := rhine.SerializeStructure[rhine.Dsp](dsp)
	dspseri, err := rhine.SerializeCBOR(dsp)
	//log.Printf("DSP, serialized: %+v", dsp)

	if err != nil {
		return res, err
	}

	res = &pf.DSProofRetResponse{DSPBytes: dspseri}
	return res, nil

}

func (s *AggServer) SubmitNDS(ctx context.Context, in *pf.SubmitNDSRequest) (*pf.SubmitNDSResponse, error) {

	res := &pf.SubmitNDSResponse{}

	log.Printf("SubmitNDS service called with RID: %s\n", rhine.EncodeBase64(in.Rid))
	//log.Printf("Received request %+v", in)

	// Construct rhine representation of Lwits
	var LogWitnessList []rhine.Lwit
	for _, lwit := range in.Lwits {
		newLwit := rhine.Lwit{
			Signature: lwit.Sig,
			NdsBytes:  lwit.NdsHash,
			Log:       &rhine.Log{Name: lwit.Log},
			LogList:   lwit.DesignatedLogs,
		}
		LogWitnessList = append(LogWitnessList, newLwit)
	}

	// Parse Pcert
	pcert, errpcertparse := x509.ParseCertificate(in.Rcertp)
	if errpcertparse != nil {
		return res, errpcertparse
	}

	// Parse in RSig
	psr := rhine.CreatePsr(pcert, &rhine.RhineSig{Data: in.Acsrpayload, Signature: in.Acsrsignature})

	// Check that ACSR was signed by Parent and
	// Check that the csr is signed by the Child
	// And check that child and parent are what they say
	if errpsr := psr.Verify(s.AggManager.CertPool); errpsr != nil {
		return res, errpsr
	}

	// Parse NDS
	nds, errNDS := rhine.BytesToNds(in.Nds)
	if errNDS != nil {
		return res, errNDS
	}

	// Check NDS against CSR
	if !nds.CheckAgainstCSR(psr.GetCsr()) {
		log.Printf("Failed check of NDS against CSR: %+v ", nds)
		return res, errors.New("Failed check of NDS against CSR at aggregator")
	}

	// Check Correct Signature on NDS
	if err := nds.VerifyNDS(s.AggManager.Ca.Pubkey); err != nil {
		return res, err
	}

	log.Println("NDS is correctly signed.")

	// Step 13 Checks
	if !rhine.VerifyLwitSlice(LogWitnessList, s.AggManager.LogMap) {
		return res, errors.New("Aggregator: One of the LogWitness failed verification!")
	}

	//log.Println("Log witnesses are valid")

	// Match Lwit and NDS
	if !nds.MatchWithLwits(LogWitnessList) {
		return res, errors.New("Aggregator: Lwit did not match with NDS")
	}

	log.Println("Log witness list matches NDS")

	acfm, errAccNDS := s.AggManager.AcceptNDSAndStore(nds)
	if errAccNDS != nil {
		return res, errAccNDS
	}

	log.Println("NDS Submission has been accepted.")

	acfmBytes, erracfm := acfm.ConfirmToTransportBytes()
	if erracfm != nil {
		return res, erracfm
	}

	res = &pf.SubmitNDSResponse{
		Acfmg: acfmBytes,
		Rid:   in.Rid,
	}

	log.Printf("SubmitNDSResponse sent for RID: %s\n", rhine.EncodeBase64(in.Rid))

	return res, nil
}

func (s *AggServer) PreLogging(ctx context.Context, in *pf.PreLoggingRequest) (*pf.PreLoggingResponse, error) {

	res := &pf.PreLoggingResponse{}

	//log.Printf("Logging service called with RID: %s\n", rhine.EncodeBase64(in.Rid))
	//log.Printf("Received request %+v", in)

	prl, err := rhine.PrlFromBytes(in.Prl)
	if err != nil {
		return res, err
	}

	errver := prl.VerifyPrl(s.AggManager.Ca.Pubkey)
	if errver != nil {
		log.Println("Failed Verify prl")
		return res, errver
	}

	preRC, _ := x509.ParseCertificate(prl.Precert)
	nds, errnds := s.AggManager.CreateNDS(prl.Psr, preRC)
	if errnds != nil {
		return res, errnds
	}

	// Check psr
	errpsr := prl.Psr.Verify(s.AggManager.CertPool)
	if errpsr != nil {
		return res, errpsr
	}

	// Check input against DSP from local DSA
	dsp, errdsp := s.AggManager.DSProof(prl.Psr.ParentZone, prl.Psr.ChildZone)
	if errdsp != nil {
		return res, errdsp
	}

	// Check validity of dsp
	// Check if proof is correct
	// Check if pcert matches dsp
	// Check ALC and ALP compatibility
	if !(&dsp).Verify(s.AggManager.PubKey, prl.Psr.ChildZone, prl.Psr.Pcert, prl.Psr.GetAlFromCSR()) {
		log.Println("Verification of dsp failed")
		return res, errors.New("Verification of DSP failed / Checks against it failed")
	}

	log.Println("Local DSP valid, proof is correct, corresponds to ParentCert")

	att, errconf := rhine.CreateConfirm(0, nds, s.AggManager.Agg.Name, rhine.DSum{}, s.AggManager.GetPrivKey())
	if errconf != nil {
		return res, errconf
	}
	attbyte, errbyt := (att).ConfirmToTransportBytes()
	if errbyt != nil {
		return res, errbyt
	}

	res = &pf.PreLoggingResponse{
		Att: attbyte,
	}

	//log.Printf("SubmitNDSResponse sent for RID: %s\n", rhine.EncodeBase64(in.Rid))

	return res, nil
}

func (s *AggServer) Logging(ctx context.Context, in *pf.LoggingRequest) (*pf.LoggingResponse, error) {

	res := &pf.LoggingResponse{}

	//log.Printf("Logging service called with RID: %s\n", rhine.EncodeBase64(in.Rid))
	//log.Printf("Received request %+v", in)

	lreq, err := rhine.LreqFromBytes(in.Lreq)
	if err != nil {
		return res, err
	}

	errlr := lreq.VerifyLreq(s.AggManager.Ca.Pubkey)
	if err != nil {
		return res, errlr
	}

	// Verify atts
	if !rhine.VerifyAggConfirmSlicePtr(lreq.Atts, s.AggManager.AggMap) {
		log.Println("Failed Att verify")
		return res, errors.New("Att verification fail")
	}

	att, errconf := rhine.CreateConfirm(0, lreq.Nds, s.AggManager.Agg.Name, rhine.DSum{}, s.AggManager.GetPrivKey())
	if errconf != nil {
		return res, errconf
	}
	attbyte, errbyt := (att).ConfirmToTransportBytes()
	if errbyt != nil {
		return res, errbyt
	}

	res = &pf.LoggingResponse{
		LogConf: attbyte,
	}

	//log.Printf("SubmitNDSResponse sent for RID: %s\n", rhine.EncodeBase64(in.Rid))

	return res, nil
}

func (s *AggServer) StartLogres(ctx context.Context, in *pf.StartLogresRequest) (*pf.StartLogresResponse, error) {
	res := &pf.StartLogresResponse{}

	

	return res, nil

}


