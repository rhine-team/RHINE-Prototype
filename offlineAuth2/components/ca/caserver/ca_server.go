package caserver

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/ca"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	logp "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/log"
)

type CAServer struct {
	pf.UnimplementedCAServiceServer
	Ca *rhine.Ca
}

func (s *CAServer) SubmitNewDelegCA(ctx context.Context, in *pf.SubmitNewDelegCARequest) (*pf.SubmitNewDelegCAResponse, error) {
	res := &pf.SubmitNewDelegCAResponse{}
	log.Println("Starting SubmitDeleg")

	// Convert message to internal rhine representation
	var algo rhine.RhineSupportedAlgorithm
	if in.Acsr.Supportedalgo == 0 {
		algo = rhine.ED25519
	} else if in.Acsr.Supportedalgo == 1 {
		algo = rhine.RSAPSSSHA256
	}
	acsr := &rhine.RhineSig{
		Algorithm: algo,
		Data:      in.Acsr.Data,
		Signature: in.Acsr.Sig,
	}

	rcertp, errcert := x509.ParseCertificate(in.Rcertp)
	if errcert != nil {
		// Certificate parsing failure
		return res, errcert
	}

	// Run initial verification steps
	acc, errverif, psr := s.Ca.VerifyNewDelegationRequest(rcertp, acsr)
	if errverif != nil {
		return res, errverif
	}
	if !acc {
		return res, errors.New("Initial Delegation checked and rejected by CA")
	}

	// Now we run DSProofRet to get dsps
	//TODO multiple logs
	parzone, chizone := GetZones(psr)

	conn := getGRPCConn(s.Ca.LogList[0])

	defer conn.Close()
	c := logp.NewLogServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.DSProofRet(ctx, &ps.DSProofRetRequest{Parentzone: parzone, Childzone: chizone})
	if err != nil {
		log.Printf("No good response: %v", err)
		return res, err
	}

	// Parse the response
	dsp, errdeser := DeserializeStructure[rhine.Dsp](r.DSPBytes)
	if errdeser != nil {
		log.Printf("Error whiile deserializing dsp: %v", errdeser)
		return res, err
	}

	// Check validity of dsp
	if !(&Dsp).Verify(s.Ca.LogMap[s.Ca.LogList[0]].Pubkey) {
		log.Println("Verification of dsp failed")
		return res, err
	}

	// Create PreRC and nds
	preRC := s.Ca.CreatePoisonedCert(psr)
	nds, errnds := s.Ca.CreateNDS(psr, preRC.RawTBSCertificate)
	if errnds != nil {
		return res, errnds
	}

	log.Println(nds)
	return res, nil
	/*
		res := &ps.SubmitNewDelegCAResponse{
			ApprovalCommit: &ps.RhineSig{
				Data: data, //[]byte{0x32, 0x32},
				Sig:  sig,  //[]byte{0x22, 0x22},
			}}
		return res, nil
	*/
}
