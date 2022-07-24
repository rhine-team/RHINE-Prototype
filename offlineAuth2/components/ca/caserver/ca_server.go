package caserver

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth2/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/ca"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"

	agg "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/aggregator"
	logp "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/log"
)

type CAServer struct {
	pf.UnimplementedCAServiceServer
	Ca *rhine.Ca
}

func (s *CAServer) SubmitNewDelegCA(ctx context.Context, in *pf.SubmitNewDelegCARequest) (*pf.SubmitNewDelegCAResponse, error) {
	res := &pf.SubmitNewDelegCAResponse{}
	log.Printf("Received NewDeleg from Child with RID %s", rhine.EncodeBase64(in.Rid))

	acsr := &rhine.RhineSig{
		Data:      in.Acsr.Data,
		Signature: in.Acsr.Sig,
	}

	rcertp, errcert := x509.ParseCertificate(in.Rcertp)
	if errcert != nil {
		// Certificate parsing failure
		log.Println("Failed to parse RCertParent")
		return res, errcert
	}

	// Run initial verification steps
	acc, errverif, psr := s.Ca.VerifyNewDelegationRequest(rcertp, acsr)
	if errverif != nil {
		log.Println("Error during inital Checks!")
		return res, errverif
	}
	if !acc {
		log.Println("Initial Checks failed!")
		return res, errors.New("Initial Delegation checked and rejected by CA")
	}

	log.Println("Initial verification steps passed, procceding with DSP")

	// Now we run DSProofRet to get dsps
	conn := rhine.GetGRPCConn(s.Ca.LogList[0])

	defer conn.Close()
	c := logp.NewLogServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	dspRequest := &logp.DSProofRetRequest{Parentzone: psr.ChildZone, Childzone: psr.ParentZone}

	//log.Printf("Our DSPRequest %+v", dspRequest)

	r, err := c.DSProofRet(ctx, dspRequest)
	if err != nil {
		log.Printf("No good response: %v", err)
		return res, err
	}

	// Parse the response
	dsp, errdeser := rhine.DeserializeStructure[rhine.Dsp](r.DSPBytes)
	if errdeser != nil {
		log.Printf("Error while deserializing dsp: %v", errdeser)
		return res, err
	}

	//log.Printf("Our DSP Response from the log %+v", r)
	//log.Printf("Our DSP we got from the log %+v", dsp)

	// Check validity of dsp
	// Check if proof is correct
	// Check if pcert matches dsp
	// Check ALC and ALP compatibility
	if !(&dsp).Verify(s.Ca.LogMap[s.Ca.LogList[0]].Pubkey, psr.ChildZone, rcertp, psr.GetAlFromCSR()) {
		log.Println("Verification of dsp failed")
		return res, errors.New("Verification of DSP and check against it failed!")
	}

	log.Println("DSP verified with success.")

	// Create PreRC and NDS
	preRC := s.Ca.CreatePoisonedCert(psr)
	nds, errnds := s.Ca.CreateNDS(psr, preRC)
	if errnds != nil {
		return res, errnds
	}
	log.Printf("Constructed NDS looks like this: %+v", nds)

	// Open connections to loggers:
	// TODO: Multiple!
	// Reuse earlier connection
	// Reuse ctx

	ndsBytes, ndsBerr := nds.NdsToBytes()
	if ndsBerr != nil {
		return res, ndsBerr
	}

	// Construct log ACSR
	// TODO must be a better way than this
	acsrLog := &logp.RhineSig{
		Data: in.Acsr.Data,
		Sig:  in.Acsr.Sig,
	}

	rDemandLog, errDL := c.DemandLogging(ctx, &logp.DemandLoggingRequest{Acsr: acsrLog, ParentRcert: in.Rcertp, ChildPreRC: preRC.Raw, Nds: ndsBytes, Rid: in.Rid})
	if errDL != nil {
		log.Printf("No good response from log for DemandLogging: %v", errDL)
		return res, errDL
	}

	//log.Printf("Received res for Demand Logging %+v ", rDemandLog)
	log.Printf("Received response for DemandLogging ")

	// Collect Lwits
	//TODO Multiple!
	var LogWitnessList []rhine.Lwit
	var newLwit rhine.Lwit
	newLwit = rhine.Lwit{
		Rsig: &rhine.RhineSig{
			Data:      rDemandLog.LogWitness.Data,
			Signature: rDemandLog.LogWitness.Sig,
		},
		NdsBytes: rDemandLog.LogWitness.NdsHash,
		Log:      &rhine.Log{Name: rDemandLog.LogWitness.Log},
		LogList:  rDemandLog.LogWitness.DesignatedLogs,
	}
	LogWitnessList = append(LogWitnessList, newLwit)

	// Step 11: Verify Lwits
	if !rhine.VerifyLwitSlice(LogWitnessList, s.Ca.LogMap) {
		return res, errors.New("One of the LogWitness failed verification!")
	}
	// Match Lwit and NDS
	if !nds.MatchWithLwits(LogWitnessList) {
		return res, errors.New("Lwit did not match with NDS")
	}

	log.Println("All checks okay until here")

	// Send all allgregs the log witnesses
	//TODO Multiple!
	//TODO CTX reuse?
	connAgg := rhine.GetGRPCConn(s.Ca.AggList[0])
	defer conn.Close()
	cAgg := agg.NewAggServiceClient(connAgg)

	// Construct message for Aggregator containing list of log witnesses and NDS
	var lwitAggList []*agg.Lwit
	for _, lwi := range LogWitnessList {
		lw := &agg.Lwit{
			DesignatedLogs: lwi.LogList,
			Log:            lwi.Log.Name,
			NdsHash:        lwi.NdsBytes,
			Data:           lwi.Rsig.Data,
			Sig:            lwi.Rsig.Signature,
		}

		lwitAggList = append(lwitAggList, lw)
	}

	aggMsg := &agg.SubmitNDSRequest{
		Nds:   ndsBytes,
		Lwits: lwitAggList,
		Rid:   in.Rid,
	}

	rAgg, err := cAgg.SubmitNDS(ctx, aggMsg)
	if err != nil {
		return res, err
	}

	// Check Signatures on Agg_confirms and
	// Check match between nds and dsum

	//log.Printf("Response by AGG, %+v", rAgg)
	log.Println("Response received by aggregator for SubmitNDS")

	// TODO Multiple
	// Collect AggConfirms
	aggConfirmList := []rhine.Confirm{}
	aggConfirmListBytes := [][]byte{}

	aggConf, errTranspConf := rhine.TransportBytesToConfirm(rAgg.Acfmg)
	if errTranspConf != nil {
		return res, errTranspConf
	}

	aggConfirmList = append(aggConfirmList, *aggConf)
	aggConfirmListBytes = append(aggConfirmListBytes, rAgg.Acfmg)

	// Check match of confirms with nds
	if !nds.MatchWithConfirm(aggConfirmList) {
		return res, errors.New("One of the AggConfirms did not match the NDS")
	}
	// Check if Confirms are correctly signed
	if !rhine.VerifyAggConfirmSlice(aggConfirmList, s.Ca.AggMap) {
		return res, errors.New("An AggConfirm was not correctly signed")
	}

	log.Println("CA: All AggConfirms checked with success.")

	// TODO Multiple
	// Communicate back to the log and hand in the AggConfirms
	// Connection already established (reuse ctx):
	rSubAcfm, errSubAcfm := c.SubmitACFM(ctx, &logp.SubmitACFMRequest{Acfms: aggConfirmListBytes, Rid: in.Rid})
	if errSubAcfm != nil {
		return res, errSubAcfm
	}

	// Collect LogConfirms
	logConfirmList := []rhine.Confirm{}
	logConfirmListBytes := [][]byte{}

	logConf, errTranspConfL := rhine.TransportBytesToConfirm(rSubAcfm.Lcfm)
	if errTranspConfL != nil {
		return res, errTranspConfL
	}

	logConfirmList = append(logConfirmList, *logConf)
	aggConfirmListBytes = append(logConfirmListBytes, rSubAcfm.Lcfm)

	// Check if LogConfirms are correctly signed
	if !rhine.VerifyLogConfirmSlice(logConfirmList, s.Ca.LogMap) {
		return res, errors.New("A LogConfirm was not correctly signed")
	}

	//TODO SCT Checks!

	// Issue Cert!
	chilcert := s.Ca.IssueRHINECert(preRC, psr, rSubAcfm.SCT)

	//log.Println(chilcert)

	res = &pf.SubmitNewDelegCAResponse{
		Rcertc: chilcert.Raw,
		Lcfms:  logConfirmListBytes,
		Rid:    in.Rid,
	}

	return res, nil

}
