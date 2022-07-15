package pserver

import (
	"context"
	"log"
	"net"

	ps "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/parentserver"
	//"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"
	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth2/cbor"
	//"google.golang.org/grpc"
)

type PServer struct {
	ps.UnimplementedParentServiceServer
	Zm *rhine.ZoneManager
}

func (s *PServer) InitDelegation(ctx context.Context, in *ps.InitDelegationRequest) (*ps.InitDelegationResponse, error) {
	res := &InitDelegationResponse{}

	// Verify the received csr
	csr, err := s.Zm.VerifyChildCSR(in.Csr)
	if err != nil {
		return res, nil
	}

	// Generate Acsr
	psr := s.Zm.CreatePSR(csr * Csr)
	rsig := psr.GetRhineSig()

	res := &ps.InitDelegationResponse{
		ApprovalCommit: &ps.RhineSig{
			Data: rsig.Data,
			Sig:  rsig.Sig,
		},
		Rcertp: s.Zm.rcert.Raw,
	}
	return res, nil
}

/*
var port = "50015"

type pServer struct {
	ps.UnimplementedParentServiceServer
}

func (s *pServer) InitDelegation(ctx context.Context, in *ps.InitDelegationRequest) (*ps.InitDelegationResponse, error) {
	res := &ps.InitDelegationResponse{
		ApprovalCommit: &ps.RhineSig{
			Data: data, //[]byte{0x32, 0x32},
			Sig:  sig,  //[]byte{0x22, 0x22},
		}}
	return res, nil
}

func main() {
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}

	s := grpc.NewServer()
	ps.RegisterParentServiceServer(s, &pServer{})

	if err := s.Serve(lis); err != nil {
		log.Fatalf("Serving failed: %v", err)
	}
}
*/
