package aggserver

import (
	"context"
	"errors"
	"log"

	//"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth2/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/aggregator"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"
	//"google.golang.org/grpc"
)

type AggServer struct {
	pf.UnimplementedAggServiceServer
	AggManager *rhine.AggManager
}

func (s *AggServer) SubmitNDS(ctx context.Context, in *pf.SubmitNDSRequest) (*pf.SubmitNDSResponse, error) {
	res := &pf.SubmitNDSResponse{}
	log.Println("Received a SubmitNDSRequest")
	//log.Printf("Received request %+v", in)

	// Construct rhine representation of Lwits
	var LogWitnessList []rhine.Lwit
	for _, lwit := range in.Lwits {
		newLwit := rhine.Lwit{
			Rsig: &rhine.RhineSig{
				Data:      lwit.Data,
				Signature: lwit.Sig,
			},
			NdsBytes: lwit.NdsHash,
			Log:      &rhine.Log{Name: lwit.Log},
			LogList:  lwit.DesignatedLogs,
		}
		LogWitnessList = append(LogWitnessList, newLwit)
	}
	//log.Printf("List of all log witnesses: %+v \n", LogWitnessList)

	// Parse NDS
	nds, errNDS := rhine.BytesToNds(in.Nds)
	if errNDS != nil {
		return res, errNDS
	}
	//log.Println("NDS deserialized:", nds)

	// Check Correct Signature on NDS
	if err := nds.VerifyNDS(s.AggManager.Ca.Pubkey); err != nil {
		return res, err
	}

	// Step 13 Checks
	if !rhine.VerifyLwitSlice(LogWitnessList, s.AggManager.LogMap) {
		return res, errors.New("Aggregator: One of the LogWitness failed verification!")
	}
	// Match Lwit and NDS
	if !nds.MatchWithLwits(LogWitnessList) {
		return res, errors.New("Aggregator: Lwit did not match with NDS")
	}

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

	return res, nil
}
