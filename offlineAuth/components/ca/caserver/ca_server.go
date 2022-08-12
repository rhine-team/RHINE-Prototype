package caserver

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/ca"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"

	agg "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/aggregator"
	logp "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/log"
)

type CAServer struct {
	pf.UnimplementedCAServiceServer
	Ca *rhine.Ca
}

func (s *CAServer) SubmitNewDelegCA(ctx context.Context, in *pf.SubmitNewDelegCARequest) (*pf.SubmitNewDelegCAResponse, error) {
	res := &pf.SubmitNewDelegCAResponse{}

	// Set timeout
	timeout := time.Second * 10

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

	// Make dspRequest
	dspRequest := &logp.DSProofRetRequest{Childzone: psr.ChildZone, Parentzone: psr.ParentZone}

	clientsLogger := []logp.LogServiceClient{}
	// Make connections for all designated loggers
	for i, logger := range psr.GetLogs() {
		//TODO: maybe check if corresponds to configed log list
		conn := rhine.GetGRPCConn(logger)
		defer conn.Close()
		clientsLogger = append(clientsLogger, logp.NewLogServiceClient(conn))

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		r, err := clientsLogger[i].DSProofRet(ctx, dspRequest)
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
		if !(&dsp).Verify(s.Ca.LogMap[logger].Pubkey, psr.ChildZone, rcertp, psr.GetAlFromCSR()) {
			log.Println("Verification of dsp failed")
			return res, errors.New("Verification of DSP and check against it failed!")
		}

		log.Println("DSP verified with success.")

	}

	// Create PreRC and NDS
	preRC := s.Ca.CreatePoisonedCert(psr)
	nds, errnds := s.Ca.CreateNDS(psr, preRC)
	if errnds != nil {
		return res, errnds
	}
	log.Printf("Constructed NDS looks like this: %+v", nds)

	// Reuse earlier connection

	ndsBytes, ndsBerr := nds.NdsToBytes()
	if ndsBerr != nil {
		return res, ndsBerr
	}

	// Construct log ACSR
	acsrLog := &logp.RhineSig{
		Data: in.Acsr.Data,
		Sig:  in.Acsr.Sig,
	}

	var LogWitnessList []rhine.Lwit
	// Make connections for all designated loggers
	for i, _ := range psr.GetLogs() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		rDemandLog, errDL := clientsLogger[i].DemandLogging(ctx, &logp.DemandLoggingRequest{Acsr: acsrLog, ParentRcert: in.Rcertp, ChildPreRC: preRC.Raw, Nds: ndsBytes, Rid: in.Rid})
		if errDL != nil {
			log.Printf("No good response from log for DemandLogging: %v", errDL)
			return res, errDL
		}

		//log.Printf("Received res for Demand Logging %+v ", rDemandLog)
		log.Printf("Received response for DemandLogging ")

		// Collect Lwits
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
	}

	// Step 11: Verify Lwits
	if !rhine.VerifyLwitSlice(LogWitnessList, s.Ca.LogMap) {
		return res, errors.New("One of the LogWitness failed verification!")
	}
	// Match Lwit and NDS
	if !nds.MatchWithLwits(LogWitnessList) {
		return res, errors.New("Lwit did not match with NDS")
	}

	log.Println("LOG_WITNESS verified and matched with NDS")

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

	// Send all allgregs the log witnesses
	clientsAggreg := []agg.AggServiceClient{}
	aggConfirmList := []rhine.Confirm{}
	aggConfirmListBytes := [][]byte{}
	// Make connections for all designated loggers
	for _, aggregat := range nds.Nds.Agg {
		connAgg := rhine.GetGRPCConn(aggregat)
		defer connAgg.Close()
		cAgg := agg.NewAggServiceClient(connAgg)
		clientsAggreg = append(clientsAggreg, cAgg)

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		rAgg, err := cAgg.SubmitNDS(ctx, aggMsg)
		if err != nil {
			return res, err
		}

		log.Println("Response received by aggregator for SubmitNDS")

		// Collect received confirms

		aggConf, errTranspConf := rhine.TransportBytesToConfirm(rAgg.Acfmg)
		if errTranspConf != nil {
			return res, errTranspConf
		}

		aggConfirmList = append(aggConfirmList, *aggConf)
		aggConfirmListBytes = append(aggConfirmListBytes, rAgg.Acfmg)
	}

	// Check Signatures on Agg_confirms and
	// Check match between nds and dsum

	// Check match of confirms with nds
	if !nds.MatchWithConfirm(aggConfirmList) {
		return res, errors.New("One of the AggConfirms did not match the NDS")
	}
	// Check if Confirms are correctly signed
	if !rhine.VerifyAggConfirmSlice(aggConfirmList, s.Ca.AggMap) {
		return res, errors.New("An AggConfirm was not correctly signed")
	}

	log.Println("CA: All AggConfirms checked with success.")

	// Communicate back to the log and hand in the AggConfirms
	// Connection already established :

	// Collect LogConfirms
	logConfirmList := []rhine.Confirm{}
	logConfirmListBytes := [][]byte{}
	SCTS := [][]byte{}
	pubKeyInOrder := []any{}
	for i, logger := range psr.GetLogs() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		rSubAcfm, errSubAcfm := clientsLogger[i].SubmitACFM(ctx, &logp.SubmitACFMRequest{Acfms: aggConfirmListBytes, Rid: in.Rid})
		if errSubAcfm != nil {
			return res, errSubAcfm
		}

		logConf, errTranspConfL := rhine.TransportBytesToConfirm(rSubAcfm.Lcfm)
		if errTranspConfL != nil {
			return res, errTranspConfL
		}

		// Collect Confirms
		logConfirmList = append(logConfirmList, *logConf)
		logConfirmListBytes = append(logConfirmListBytes, rSubAcfm.Lcfm)
		SCTS = append(SCTS, rSubAcfm.SCT)
		pubKeyInOrder = append(pubKeyInOrder, s.Ca.LogMap[logger].Pubkey)
	}

	// Check if LogConfirms are correctly signed
	if !rhine.VerifyLogConfirmSlice(logConfirmList, s.Ca.LogMap) {
		return res, errors.New("A LogConfirm was not correctly signed")
	}
	log.Println("CA: All LogConfirms checked and valid")

	// Issue Cert!
	chilcert := s.Ca.IssueRHINECert(preRC, psr, SCTS)

	// Check SCT
	// We check SCT after embedding of SCTs, to reuse functions
	if err := rhine.VerifyEmbeddedSCTs(chilcert, s.Ca.CACertificate, pubKeyInOrder); err != nil {
		log.Println("CA: Verification of atleast one SCT failed")
		return res, err
	}
	/*
		if err := rhine.VerifyEmbeddedSCTs(chilcert, s.Ca.CACertificate, s.Ca.LogMap[s.Ca.LogList[0]].Pubkey); err != nil {
			log.Println("CA: Verification of atleast one SCT failed")
			return res, err
		}
	*/
	//log.Println(chilcert)

	res = &pf.SubmitNewDelegCAResponse{
		Rcertc: chilcert.Raw,
		Lcfms:  logConfirmListBytes,
		Rid:    in.Rid,
	}

	return res, nil

}
