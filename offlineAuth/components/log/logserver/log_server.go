package logserver

import (
	"context"
	"errors"
	"log"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/log"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
	//"google.golang.org/grpc"
)

type LogServer struct {
	pf.UnimplementedLogServiceServer
	LogManager *rhine.LogManager
}

func (s *LogServer) DSProofRet(ctx context.Context, in *pf.DSProofRetRequest) (*pf.DSProofRetResponse, error) {
	res := &pf.DSProofRetResponse{}

	log.Printf("Received a DSProofRet request: %+v", in)

	dsp, dsperr := s.LogManager.DSProof(in.Parentzone, in.Childzone)
	if dsperr != nil {
		return res, dsperr
	}

	// Encode and send
	dspseri, err := rhine.SerializeStructure[rhine.Dsp](dsp)
	//log.Printf("DSP, serialized: %+v", dsp)

	if err != nil {
		return res, err
	}

	res = &pf.DSProofRetResponse{DSPBytes: dspseri}
	return res, nil

}

func (s *LogServer) DemandLogging(ctx context.Context, in *pf.DemandLoggingRequest) (*pf.DemandLoggingResponse, error) {
	res := &pf.DemandLoggingResponse{}

	log.Printf("DemandLogging service called with RID: %s\n", rhine.EncodeBase64(in.Rid))
	//log.Printf("Request looks like: %+v ", in)

	// Create RHINE internal representations
	acsr := &rhine.RhineSig{
		Data:        in.Acsr.Data,
		Signature:   in.Acsr.Sig,
		DataPostfix: in.Acsr.DataPostfix,
	}
	// Parent certificate
	rcertp, errP := x509.ParseCertificate(in.ParentRcert)
	if errP != nil {
		log.Println("Parent Certificate parsing failure")
		return res, errP
	}
	// Child PreCert
	prercp, errC := x509.ParseCertificate(in.ChildPreRC)
	if errC != nil {
		log.Println("Child certificate parsing Failure")
		return res, errC
	}
	//log.Println("Child PreCert:", prercp)

	// NDS
	nds, errNDS := rhine.BytesToNds(in.Nds)
	if errNDS != nil {
		return res, errNDS
	}
	//log.Println("NDS deserialized:", nds)

	errVerification, _, lwit := s.LogManager.VerifyNewDelegationRequestLog(rcertp, acsr, prercp, nds)
	if errVerification != nil {
		return res, errVerification
	}

	log.Printf("Lwit constructed %+v ", lwit)

	// Send back the Lwit
	res = &pf.DemandLoggingResponse{
		LogWitness: &pf.Lwit{
			DesignatedLogs: lwit.LogList,
			Log:            lwit.Log.Name,
			NdsHash:        lwit.NdsBytes,
			Data:           lwit.Rsig.Data,
			Sig:            lwit.Rsig.Signature,
		},
		Rid: in.Rid,
	}

	//log.Println("Test success", psr)
	return res, nil
}

func (s *LogServer) SubmitACFM(ctx context.Context, in *pf.SubmitACFMRequest) (*pf.SubmitACFMResponse, error) {
	res := &pf.SubmitACFMResponse{}

	aggConfirmList := []rhine.Confirm{}
	for _, aggConfBytes := range in.Acfms {
		aggConf, errTranspConf := rhine.TransportBytesToConfirm(aggConfBytes)
		if errTranspConf != nil {
			return res, errTranspConf
		}
		aggConfirmList = append(aggConfirmList, *aggConf)
	}

	// Retrieve nds, etc... from the RequestCache
	rq, ok := s.LogManager.RequestCache[string(in.Rid)]
	if !ok {
		return res, errors.New("Wrong RID on this Request")
	}
	nds := rq.NDS
	precert := rq.PreRCc
	parcert := rq.ParentCert

	// Check match of confirms with nds
	if !nds.MatchWithConfirm(aggConfirmList) {
		return res, errors.New("One of the AggConfirms did not match the NDS")
	}
	// Check if Confirms are correctly signed
	if !rhine.VerifyAggConfirmSlice(aggConfirmList, s.LogManager.AggMap) {
		return res, errors.New("An AggConfirm was not correctly signed")
	}

	log.Println("Log: All AggConfirms checked with success.")

	// Create LogConfirm and SCTs
	loggconf, sct, errFinishDeleg := s.LogManager.FinishInitialDelegLog(aggConfirmList[0].Dsum, nds, parcert.DNSNames[0], precert)
	if errFinishDeleg != nil {
		return res, errFinishDeleg
	}

	// Create response
	lconfByte, _ := loggconf.ConfirmToTransportBytes()

	res = &pf.SubmitACFMResponse{
		Lcfm: lconfByte,
		SCT:  sct,
		Rid:  in.Rid,
	}

	log.Println("Logger: SCT created, send response")

	return res, nil

}
