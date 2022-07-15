package logserver

import (
	"context"
	"errors"
	"log"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth2/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/log"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"
	//"google.golang.org/grpc"
)

type LogServer struct {
	pf.UnimplementedLogServiceServer
	LogManager *rhine.LogManager
}

func (s *LogServer) DSProofRet(ctx context.Context, in *pf.DSProofRetRequest) (*pf.DSProofRetResponse, error) {
	res := pf.DSProofRetResponse{}

	dsp := s.LogManager.DSProof(in.Parentzone, in.Childzone)
	// Encode and send
	res = pf.DSProofRetResponse{DSPBytes: rhine.SerializeStructure[rhine.Dsp](dsp)}
	return &res, nil

}

func (s *LogServer) DemandLogging(ctx context.Context, in *pf.DemandLoggingRequest) (*pf.DemandLoggingResponse, error) {
	res := pf.DemandLoggingResponse{}

	// Create RHINE internal representations
	acsr := &rhine.RhineSig{
		Data:        in.Acsr.Data,
		Sign:        in.Acsr.Sig,
		DataPostfix: in.Acsr.DataPostfix,
	}
	// Parent certificate
	rcertp := x509.ParseCertificate(in.ParentRcert)
	// Child PreCert
	prercp := x509.ParseCertificate(in.ChildPreRC)
	// NDS
	nds, err := BytesToNds(in.Nds)

	// Verify acsr with parent cert
	if !acsr.Verify(rcertp.PublicKey) {
		return res, errors.New("Verification of ACSR with ParentCert failed")
	}
	return res, nil
}
