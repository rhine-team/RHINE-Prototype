// LogClient provides functions to perform operations on a Trillian Log.

package tclient

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/trillian"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/types"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"io/ioutil"
	"log"
)

type LogClient interface {
	LogEECerts(logID int64, domains []string, op string)
	LogCertFromFile(logID int64, fileName string)
	LogCert(cert *x509.Certificate, logID int64)
	RetrieveCerts(logID, lastIdx int64) []*trillian.LogLeaf
	RetrieveSignedLogRoot(logID int64) *types.LogRootV1
	GetPoP(logID int64, domain string) (*trillian.Proof, *types.LogRootV1, error)
	GetPoC(logID, first, second int64) (*trillian.Proof, *types.LogRootV1, error)
	GetEntriesByRange(logID, start, count int64) ([]*trillian.LogLeaf, error)
	Close()
}

type logClient struct {
	connection *grpc.ClientConn
	client     trillian.TrillianLogClient
	logPK      crypto.PublicKey
}

// To avoid import cycle
func logError(msg string, err error) {
	if err != nil {
		log.Printf(msg, err)
	}
}

// Create a new LogClient
func NewLogClient(address, logPk string, maxReceiveMessageSize int) LogClient {
	log.Println("Opening Connection to Trillian Log at " + address + "...")
	g, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithMaxMsgSize(maxReceiveMessageSize))
	logError("Failed connecting to Trillian log at "+address+": %s", err)
	log.Println("Connection Opened")

	client := trillian.NewTrillianLogClient(g)

	pubKey, err := common.LoadPK(logPk)
	logError("Failed to load public key: %s", err)

	tlClient := logClient{connection: g, client: client, logPK: pubKey}
	return &tlClient
}

// Log multiple (op, domain) pairs to the given Log
func (tc *logClient) LogEECerts(logID int64, domains []string, op string) {
	log.Printf("Contacting Log to add %d EECerts to the tree...", len(domains))

	var leaf *trillian.LogLeaf
	var code codes.Code
	var resp *trillian.QueueLeafResponse
	var l *trillian.QueuedLogLeaf
	var err error

	client := tc.client
	for idx, domain := range domains {
		leafValue := fmt.Sprintf("(%s, %s)", op, domain)
		leaf = &trillian.LogLeaf{LeafValue: []byte(leafValue)}
		qlReq := &trillian.QueueLeafRequest{LogId: logID, Leaf: leaf}

		resp, err = client.QueueLeaf(context.Background(), qlReq)
		logError("Failed receiving response from log: %s", err)

		l = resp.QueuedLeaf
		code = codes.Code(l.GetStatus().GetCode())
		if code != codes.OK && code != codes.AlreadyExists {
			log.Fatalf("Bad return status %d: %v:", idx, l.GetStatus())
		}

		log.Printf("...EECert %d queued, (status, leaf index): (%v, %d)", idx, code, l.Leaf.LeafIndex)
	}
}

// Retrieve multiple leaves from the given log, starting from lastIdx
func (tc *logClient) RetrieveCerts(logID, lastIdx int64) []*trillian.LogLeaf {
	client := tc.client
	ctx := context.Background()

	desRoot := tc.RetrieveSignedLogRoot(logID)

	log.Println("Tree size:", desRoot.TreeSize)
	// log.Printf("hash %s", base64.StdEncoding.EncodeToString(desRoot.RootHash))
	var leaves []*trillian.LogLeaf
	log.Println("Retrieving Certs...")

	var i uint64
	if lastIdx == 0 {
		i = 0
	} else {
		i = uint64(lastIdx) + 1
	}

	for i < desRoot.TreeSize {
		gReq := &trillian.GetLeavesByRangeRequest{LogId: logID, StartIndex: int64(i), Count: 10}
		resp, err := client.GetLeavesByRange(ctx, gReq)
		logError("Failed getting leaves by range: %s", err)

		leaves = append(leaves, resp.Leaves...)
		log.Println("Received", len(resp.Leaves), "leaves")
		var currentLeaf *trillian.LogLeaf
		for j := 0; j < len(resp.Leaves); j++ {
			currentLeaf = resp.Leaves[j]
			cert, err := common.X509ParseCertificates(currentLeaf.LeafValue)
			logError("Couldn't unmarshal certificate from asn1: %s", err)
			log.Printf("Leaf %d (value, leafidentityhash, merkleleafhash): %s %x %x", currentLeaf.LeafIndex, common.X509CertChainToString(cert), currentLeaf.LeafIdentityHash, currentLeaf.MerkleLeafHash)
			i++
		}
	}
	log.Println("Certs retrieved:", len(leaves))
	return leaves
}

// Fetch a Log PoP
func (tc *logClient) GetPoP(logID int64, domain string) (*trillian.Proof, *types.LogRootV1, error) {
	desRoot := tc.RetrieveSignedLogRoot(logID) // should return err
	leaf := fmt.Sprintf("(add, %s)", domain)
	prefixedHash := append([]byte{ct.TreeLeafPrefix}, []byte(leaf)...)
	leafHash := sha256.Sum256(prefixedHash)

	popReq := trillian.GetInclusionProofByHashRequest{
		LogId:    logID,
		LeafHash: leafHash[:],
		TreeSize: int64(desRoot.TreeSize),
	}

	log.Println("Getting Proof of Presence...")
	popRsp, err := tc.client.GetInclusionProofByHash(context.Background(), &popReq)

	if err != nil {
		return nil, nil, fmt.Errorf("failed to get PoP: %s", err)
	}

	if popRsp.Proof[0].String() == "" {
		return nil, nil, errors.New("empty PoP received")
	}

	for idx, node := range popRsp.Proof[0].Hashes {
		if len(node) != sha256.Size {
			return nil, nil, fmt.Errorf("inconsistent size for node %d", idx)
		}
	}

	log.Println("...done")
	return popRsp.Proof[0], desRoot, nil

}

// Fetch a PoC
func (tc *logClient) GetPoC(logID, first, second int64) (*trillian.Proof, *types.LogRootV1, error) {
	log.Printf("Retrieving PoC between tree sizes %d, %d", first, second)

	req := trillian.GetConsistencyProofRequest{
		LogId:          logID,
		FirstTreeSize:  first,
		SecondTreeSize: second,
	}

	resp, err := tc.client.GetConsistencyProof(context.Background(), &req)
	if err != nil {
		return nil, &types.LogRootV1{}, fmt.Errorf("failed to get PoC: %s", err)
	}

	currentRoot := tc.RetrieveSignedLogRoot(logID)
	if currentRoot.TreeSize < uint64(second) {
		return nil, &types.LogRootV1{}, fmt.Errorf("current root tree size %d < provided second tree size %d", currentRoot.TreeSize, second)
	}

	if !checkPath(resp.Proof.Hashes) {
		return nil, &types.LogRootV1{}, fmt.Errorf("trillian log returned invalid PoC: %v", resp.Proof)
	}

	return resp.Proof, currentRoot, nil

}

// Retrieve count leaves starting from start, from the given Log
func (tc *logClient) GetEntriesByRange(logID, start, count int64) ([]*trillian.LogLeaf, error) {
	log.Printf("Retrieving %d entries starting from %d", count, start)

	req := trillian.GetLeavesByRangeRequest{
		LogId:      logID,
		StartIndex: start,
		Count:      count,
	}

	resp, err := tc.client.GetLeavesByRange(context.Background(), &req)
	if err != nil {
		return nil, fmt.Errorf("failed to GetLeavesByRange: %s", err)
	}

	currentRoot := tc.RetrieveSignedLogRoot(logID)
	if currentRoot.TreeSize <= uint64(start) {
		return nil, fmt.Errorf("tree size %d is < than start %d", currentRoot.TreeSize, start)
	}

	if len(resp.Leaves) > int(count) {
		return nil, fmt.Errorf("too many leaves: asked %d, returned %d", count, len(resp.Leaves))
	}

	for i, leaf := range resp.Leaves {
		if leaf.LeafIndex != start+int64(i) {
			return nil, fmt.Errorf("unexpected leaf index %d at index %d", leaf.LeafIndex, i)
		}
	}

	return resp.Leaves, nil
}

// Retrieve the latest Signed Log Root
func (tc *logClient) RetrieveSignedLogRoot(logID int64) *types.LogRootV1 {
	log.Println("Retrieving latest SLR...")
	tlrReq := &trillian.GetLatestSignedLogRootRequest{LogId: logID}
	tlRoot, err := tc.client.GetLatestSignedLogRoot(context.Background(), tlrReq)
	logError("Could not retrieve Trillian SLR: %s", err)
	log.Println("...done")

	log.Println("Verifying root signature...")
	desRoot, err := tcrypto.VerifySignedLogRoot(tc.logPK, 5, tlRoot.SignedLogRoot)
	logError("Failed to verify log root signature: %s", err)
	log.Println("...succeeded")

	return desRoot
}

func (tc *logClient) Close() {
	tc.connection.Close()
}

func checkPath(path [][]byte) bool {
	for _, node := range path {
		if len(node) != sha256.Size {
			return false
		}
	}
	return true
}

func checkRespCode(resp *trillian.QueueLeafResponse) codes.Code {
	code := codes.Code(resp.QueuedLeaf.GetStatus().GetCode())
	if code != codes.OK && code != codes.AlreadyExists {
		log.Fatal("Bad return status:", resp.QueuedLeaf.GetStatus())
	}

	return code
}

func eeCertFromPEM(fileName string) []byte {
	var bytesCerts []byte
	content, err := ioutil.ReadFile(fileName)

	logError("Failed to read specified file: %s", err)

	for {
		var block *pem.Block
		block, content = pem.Decode(content)

		if block == nil {
			return bytesCerts
		}

		if block.Type != "CERTIFICATE" {
			log.Fatal("Block contains data other than certificates.")
		}

		bytesCerts = append(bytesCerts, block.Bytes...)
	}
}

func byteCertFromPEM(fileName string) []byte {
	content, err := ioutil.ReadFile(fileName)
	logError("Failed to read specified file: %s", err)

	block, _ := pem.Decode(content)
	if block == nil {
		log.Fatalf("Failed to decode certificate: '%s'", content)
	}
	if block.Type != "CERTIFICATE" {
		log.Fatal("Block contains data other than certificates.")
	}

	return block.Bytes
}

/* FUNCTIONS USED ONLY BY trillian/main.go */

func (tc *logClient) LogCert(cert *x509.Certificate, logID int64) {
	log.Println("Contacting Log to add " + cert.DNSNames[0] + " to the tree...")
	leafValue := cert.Raw

	client := tc.client

	tlLeaf := &trillian.LogLeaf{LeafValue: leafValue}
	qlReq := &trillian.QueueLeafRequest{LogId: logID, Leaf: tlLeaf}

	resp, err := client.QueueLeaf(context.Background(), qlReq)
	logError("Failed receiving response from log: %s", err)

	code := checkRespCode(resp)
	log.Printf("cert queued, (status, leaf index): (%v, %d)", code, resp.QueuedLeaf.Leaf.LeafIndex)
}

func (tc *logClient) LogCertFromFile(logID int64, fileName string) {
	log.Println("Contacting Log to add " + fileName + " to the tree...")
	leafValue, err := leafValueFromCertificateFile(fileName)
	logError("Failed to prepare Leaf Value to log: %s", err)

	client := tc.client

	tlLeaf := &trillian.LogLeaf{LeafValue: leafValue}
	qlReq := &trillian.QueueLeafRequest{LogId: logID, Leaf: tlLeaf}

	resp, err := client.QueueLeaf(context.Background(), qlReq)
	logError("Failed receiving response from log: %s", err)

	code := checkRespCode(resp)
	log.Printf("cert queued, (status, leaf index): (%v, %d)", code, resp.QueuedLeaf.Leaf.LeafIndex)
}

func leafValueFromCertificateFile(fileName string) ([]byte, error) {
	certBytes, err := common.X509CertChainBytesFromPEM(fileName)
	if err != nil {
		return nil, err
	}

	return certBytes, nil

	// data, err := asn1.Marshal(cert)
	// if err != nil {
	// 	return nil, err
	// }

	// return data, nil
}
