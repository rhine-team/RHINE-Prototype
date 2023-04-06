package caserver

import (
	"context"
	"errors"

	//"fmt"
	"log"
	"math/rand"

	//"os"
	//"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/internal/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/internal/components/ca"
	"github.com/rhine-team/RHINE-Prototype/pkg/rhine"

	//"github.com/shirou/gopsutil/cpu"

	agg "github.com/rhine-team/RHINE-Prototype/internal/components/aggregator"
	//logp "github.com/rhine-team/RHINE-Prototype/internal/components/log"
)

// Set timeout
var timeout = time.Second * 30

/*
var count uint64
var f *os.File
var ft *os.File
var cpuPercent []float64

var measureT = false
var startTime time.Time
var intervalTime time.Time
*/

type SCTandLConf struct {
	sct        []byte
	lconf      rhine.Confirm
	lconfbytes []byte
}

type ConfAndBytes struct {
	bytes []byte
	conf  rhine.Confirm
}

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

	// Make dspRequest
	dspRequest := &agg.DSProofRetRequest{Childzone: psr.ChildZone, Parentzone: psr.ParentZone}

	clientsLogger := make([]agg.AggServiceClient, len(psr.GetLogs()))
	// Make connections for all designated loggers

	// Use error group to fail goroutines if network issue or dsp does not validate
	errGroup := new(errgroup.Group)

	for i, logger := range psr.GetLogs() {
		i := i
		logger := logger

		// Create connections and clients, remember to reuse later
		//conn := rhine.GetGRPCConn(logger)
		//defer conn.Close()
		conn := s.Ca.AggConnections[logger]
		clientsLogger[i] = agg.NewAggServiceClient(conn)

		errGroup.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			r, err := clientsLogger[i].DSProofRet(ctx, dspRequest)
			if err != nil {
				log.Printf("No good response: %v", err)
				return err
			}

			// Parse the response
			//dsp, errdeser := rhine.DeserializeStructure[rhine.Dsp](r.DSPBytes)
			dsp := &rhine.Dsp{}
			errdeser := rhine.DeserializeCBOR(r.DSPBytes, dsp)
			if errdeser != nil {
				log.Printf("Error while deserializing dsp: %v", errdeser)
				return errdeser
			}

			//log.Printf("Our DSP Response from the log %+v", r)
			//log.Printf("Our DSP we got from the log %+v", dsp)

			// Check validity of dsp
			// Check if proof is correct
			// Check if pcert matches dsp
			// Check ALC and ALP compatibility
			if !(dsp).Verify(s.Ca.AggMap[logger].Pubkey, psr.ChildZone, rcertp, psr.GetAlFromCSR()) {
				log.Println("Verification of dsp failed")
				//noFailureChannel <- false
				return errors.New("Verification of DSP and check against it failed!")
				//return res, errors.New("Verification of DSP and check against it failed!")
			}

			log.Println("DSP verified with success. For logger: ", logger)
			return nil
		})

	}

	log.Println("All DSProofs fine")

	// Create PreRC and NDS
	preRC := s.Ca.CreatePoisonedCert(psr)

	prl, errprl := s.Ca.CreatePRL(psr, preRC)
	if errprl != nil {
		return res, errprl
	}

	// Reuse earlier connection

	prlbytes, perr := prl.PrlToBytes()
	if perr != nil {
		return res, perr
	}

	// Wait for DSProof goroutines
	if err := errGroup.Wait(); err != nil {
		return res, err
	}
	log.Println("All DSProof routines return valid")

	// Use error group to fail goroutines if network issue or dsp does not validate
	errGroup = new(errgroup.Group)

	LogAttReturns := make(chan rhine.Confirm, len(psr.GetLogs()))
	AttList := make([]rhine.Confirm, len(psr.GetLogs()))
	AttListPtr := make([]*rhine.Confirm, len(psr.GetLogs()))

	for i, _ := range psr.GetLogs() {
		i := i
		errGroup.Go(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			rDemandLog, errDL := clientsLogger[i].PreLogging(ctx, &agg.PreLoggingRequest{Prl: prlbytes})
			if errDL != nil {
				log.Printf("No good response from log for PreLoggingReq: %v", errDL)
				return errDL
			}

			//log.Printf("Received res for Demand Logging %+v ", rDemandLog)
			log.Printf("Received response for DemandLogging ")

			//LogWitnessList = append(LogWitnessList, newLwit)
			resp, errresp := rhine.TransportBytesToConfirm(rDemandLog.Att)
			if errresp != nil {
				return errresp
			}
			LogAttReturns <- *resp
			return nil
		})
	}

	// Wait for LogWitness responses
	if err := errGroup.Wait(); err != nil {
		return res, err
	}

	// Collect the Atts from the routines
	for i := range psr.GetLogs() {
		l := <-LogAttReturns
		AttList[i] = l
		AttListPtr[i] = &l
	}

	// Verify LogAttest and match with prl
	if !rhine.VerifyAggConfirmSlice(AttList, s.Ca.AggMap) {
		return res, errors.New("Failed to verify at least one of the attestations")
	}

	log.Println("ATTS list verified")

	// Communicate back to the log
	// Connection already established :

	nds, errnds := s.Ca.CreateNDS(psr, preRC)
	if errnds != nil {
		return res, errnds
	}
	log.Printf("Constructed NDS looks like this: %+v", nds)

	lr := &rhine.Lreq{
		Logger: psr.GetLogs()[0],
		Nds:    nds,
		Atts:   AttListPtr,
	}
	if err := lr.SignLreq(s.Ca.PrivateKey); err != nil {
		return res, err
	}

	lreqbytes, errlreq := lr.LreqToBytes()
	if errlreq != nil {
		return res, errlreq
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	max := len(clientsLogger) - 1
	rand.Seed(time.Now().UnixNano())
	randLoggerInd := rand.Intn(max + 1)

	rlogres, errdlog := clientsLogger[randLoggerInd].Logging(ctx, &agg.LoggingRequest{Lreq: lreqbytes})
	if errdlog != nil {
		log.Printf("Logging request failed!", errdlog)
		return res, errdlog
	}

	//log.Printf("Received res for Demand Logging %+v ", rDemandLog)
	log.Printf("Received response for DemandLogging ")

	logconfnew, errnewconf := rhine.TransportBytesToConfirm(rlogres.LogConf)
	if errnewconf != nil {
		return res, errnewconf
	}
	lcList := []rhine.Confirm{*logconfnew}

	// Check if LogConfirms are correctly signed
	if !rhine.VerifyAggConfirmSlice(lcList, s.Ca.AggMap) {
		return res, errors.New("A LogConfirm was not correctly signed")
	}
	log.Println("CA: All LogConfirm checked and valid")

	// Issue Cert!
	chilcert := s.Ca.IssueRHINECert(preRC, psr)

	AttListBytes := [][]byte{}
	for _, a := range AttList {
		ctb, _ := (&a).ConfirmToTransportBytes()
		AttListBytes = append(AttListBytes, ctb)
	}

	res = &pf.SubmitNewDelegCAResponse{
		Rcertc: chilcert.Raw,
		Lcfms:  AttListBytes,
		Rid:    in.Rid,
	}

	return res, nil

}
