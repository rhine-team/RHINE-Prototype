// MapClient provides functions to perform operations on a Trillian Map

package tclient

import (
	"context"
	"crypto"
	"encoding/asn1"
	"fmt"
	"github.com/google/trillian"
	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/maphasher"
	"github.com/google/trillian/types"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/common"
	"google.golang.org/grpc"
	"log"
	"time"
)

type EncodedMapEntry struct {
	LeafValue       []byte
	HasSubdomains   bool
	SubdomainTreeId int64
}

type MapClient interface {
	GetValues(mapID int64, mapPK crypto.PublicKey, domainRequests []string, verifyRootSignature bool, verifyInclusionProof bool) ([]*EncodedMapEntry, error)
	SetValues(mapID int64, mapPK crypto.PublicKey, leaves map[string]EncodedMapEntry, verifyRootSignature bool) error
	GetProofForDomains(mapID int64, mapPK crypto.PublicKey, domains []string) ([]Proof, error)
	GetMapRoot(mapID int64, mapPK crypto.PublicKey, verify bool) (*types.MapRootV1, error)
	GetMapPK() crypto.PublicKey
	GetMapAddress() string
	Close()
}

type mapClient struct {
	connection *grpc.ClientConn
	client     trillian.TrillianMapClient
	mapPK      crypto.PublicKey
	treeNonce  []byte
	mapAddress string
}

// Create a new MapClient
func NewMapClient(mapAddress, mapPk string, maxReceiveMessageSize int) MapClient {
	log.Println("Opening Connection to Trillian Map at " + mapAddress + "...")
	conn, err := grpc.Dial(mapAddress, grpc.WithInsecure(), grpc.WithMaxMsgSize(maxReceiveMessageSize))
	logError("Failed connecting to Trillian Map at "+mapAddress+":%s", err)
	log.Println("Connection Opened")

	client := trillian.NewTrillianMapClient(conn)

	pubKey, err := common.LoadPK(mapPk)
	logError("Failed to parse public key: %s", err)

	mapClient := mapClient{connection: conn, client: client, mapPK: pubKey, treeNonce: common.DefaultTreeNonce, mapAddress: mapAddress}
	return &mapClient
}

// get leaves from the given Map
func (mc *mapClient) GetValues(mapID int64, mapPK crypto.PublicKey, domainRequests []string, verifyRootSignature bool, verifyInclusionProof bool) ([]*EncodedMapEntry, error) {
	encodedMapEntries, _, err := mc.getValuesWithInclusionProof(mapID, mapPK, domainRequests, verifyRootSignature, verifyInclusionProof)
	return encodedMapEntries, err
}

// Add new leaves to the given Map
func (mc *mapClient) SetValues(mapID int64, mapPK crypto.PublicKey, leaves map[string]EncodedMapEntry, verifyRootSignature bool) error {
	var mapLeaves []*trillian.MapLeaf
	for k, v := range leaves {
		key := mc.mapKeyFromDomain(k)
		common.Debug("mapclient.SetValues(%s -> %x)", k, key)
		var extraData []byte
		if v.HasSubdomains {
			var err error
			extraData, err = asn1.Marshal(v.SubdomainTreeId)
			common.LogError("Couldn't marshal the subdomain's tree id: %s", err)
		}
		mapLeaves = append(mapLeaves, &trillian.MapLeaf{Index: key, LeafValue: v.LeafValue, ExtraData: extraData})
	}
	req := trillian.SetMapLeavesRequest{MapId: mapID, Leaves: mapLeaves}

	ctx := context.Background()
	common.Debug("Setting %d key:value pairs...\n", len(mapLeaves))

	resp, err := mc.client.SetLeaves(ctx, &req)
	if err != nil {
		return fmt.Errorf("failed setting leaves: %s", err)
	}

	_, err = extractMapRoot(resp.MapRoot, mapPK, verifyRootSignature)
	return err
}

// get hierarchical proof composed of inclusion proofs for each subdomain for the given domains
func (mc *mapClient) GetProofForDomains(mapID int64, mapPK crypto.PublicKey, domains []string) ([]Proof, error) {
	var proofs []Proof
	for _, domain := range domains {
		p, err := mc.getProofForDomain(mapID, mapPK, domain)
		if err != nil {
			return proofs, err
		}
		proofs = append(proofs, p)
	}
	return proofs, nil
}

func (mc *mapClient) GetMapRoot(mapID int64, mapPK crypto.PublicKey, verify bool) (*types.MapRootV1, error) {
	signedMapRoot, err := mc.getSignedMapRoot(mapID, mapPK)
	if err != nil {
		return nil, err
	}

	root, err := extractMapRoot(signedMapRoot, mapPK, verify)
	if err != nil {
		return root, fmt.Errorf("Couldn't extract map root mapID=%d, mapPK=%+v, verify=%t: %s", mapID, mapPK, verify, err)
	}

	return root, nil
}

func (mc *mapClient) GetMapPK() crypto.PublicKey {
	return mc.mapPK
}

func (mc *mapClient) GetMapAddress() string {
	return mc.mapAddress
}

func (mc *mapClient) mapKeyFromDomain(domain string) []byte {
	return common.GenerateMapKey(mc.treeNonce, domain)
}

func (mc *mapClient) getProofForDomain(mapID int64, mapPK crypto.PublicKey, domain string) (Proof, error) {
	labels, err := common.SplitE2LD(domain)
	fmt.Println("labels: ", labels)
	if err != nil {
		return nil, fmt.Errorf("Couldn't split into subdomains: %s", err)
	}

	// reverse to start at E2LD
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}

	var mapEntries []proofMapEntryType
	var inclusionProofs []InclusionProofType
	var signedMapRoot *trillian.SignedMapRoot

	signedMapRoot, err = mc.getSignedMapRoot(mapID, mapPK)
	if err != nil {
		return nil, err
	}

	for _, label := range labels {
		if label == "*" {
			break
		}
		fmt.Println("get inclusion proof for: ", label)
		encodedMapEntries, inc, err := mc.getValuesWithInclusionProof(mapID, mapPK, []string{label}, false, false)
		if err != nil {
			return nil, err
		}
		mapID = encodedMapEntries[0].SubdomainTreeId
		mapPK = nil

		var entry proofMapEntryType
		leafValue := encodedMapEntries[0].LeafValue
		if len(leafValue) > 0 {
			err := entry.UnmarshalBinary(leafValue)
			if err != nil {
				return nil, err
			}
		}
		entry.SetDomain(label)

		mapEntries = append(mapEntries, entry)
		inclusionProofs = append(inclusionProofs, inc[0])

		if len(entry.GetSubtreeRoot()) == 0 {
			break
		}
	}

	return &proofType{mapEntries: mapEntries, inclusionProofs: inclusionProofs, signedMapRoot: *signedMapRoot}, nil
}

func (mc *mapClient) getValuesWithInclusionProof(mapID int64, mapPK crypto.PublicKey, domainRequests []string, verifyRootSignature bool, verifyInclusionProof bool) ([]*EncodedMapEntry, []InclusionProofType, error) {
	common.Debug("Requesting map entries for %d (sub-)domains: %s", len(domainRequests), domainRequests)
	var keys [][]byte
	for _, domain := range domainRequests {
		keys = append(keys, mc.mapKeyFromDomain(domain))
	}
	mapLeaves, inclusionProofs, _, err := getLeaves(mapID, keys, mc.client, mapPK, verifyRootSignature, verifyInclusionProof)

	var encodedMapEntries []*EncodedMapEntry
	for _, mapLeaf := range mapLeaves {
		var hasSubdomains bool
		var subdomainTreeId int64
		if len(mapLeaf.ExtraData) != 0 {
			_, err := asn1.Unmarshal(mapLeaf.ExtraData, &subdomainTreeId)
			if err != nil {
				return nil, nil, fmt.Errorf("Couldn't unmarshal the subdomain's tree id: %s", err)
			}
			hasSubdomains = true
		}
		encodedMapEntries = append(encodedMapEntries, &EncodedMapEntry{LeafValue: mapLeaf.LeafValue, HasSubdomains: hasSubdomains, SubdomainTreeId: subdomainTreeId})
	}
	return encodedMapEntries, inclusionProofs, err
}

func getLeaves(mapID int64, keys [][]byte, client trillian.TrillianMapClient, mapPK crypto.PublicKey,
	verifyRootSignature bool, verifyInclusionProof bool) ([]*trillian.MapLeaf, []InclusionProofType, *types.MapRootV1, error) {

	req := &trillian.GetMapLeavesRequest{MapId: mapID, Index: keys}

	ctx := context.Background()
	resp, err := client.GetLeaves(ctx, req)
	if err != nil {
		return nil, nil, &types.MapRootV1{}, err
	}

	var mapLeaves []*trillian.MapLeaf
	var inclusionProofs []InclusionProofType
	root, err := extractMapRoot(resp.MapRoot, mapPK, verifyRootSignature)
	if err != nil {
		return nil, nil, root, err
	}
	for _, proof := range resp.MapLeafInclusion {
		mapLeaves = append(mapLeaves, proof.Leaf)
		inclusionProofs = append(inclusionProofs, proof.Inclusion)
		if verifyInclusionProof && merkle.VerifyMapInclusionProof(mapID, proof.Leaf, root.RootHash, proof.Inclusion, maphasher.Default) != nil {
			return mapLeaves, inclusionProofs, root, fmt.Errorf("Invalid inclusion proof: mapID = %x, leaf = %+v, root = %x, inclusion = %+v", mapID, proof.Leaf, root.RootHash, proof.Inclusion)
		}
	}
	return mapLeaves, inclusionProofs, root, nil
}

func (mc *mapClient) Close() {
	mc.connection.Close()
}

func (mc *mapClient) getSignedMapRoot(mapID int64, mapPK crypto.PublicKey) (*trillian.SignedMapRoot, error) {
	req := &trillian.GetSignedMapRootRequest{MapId: mapID}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	resp, err := mc.client.GetSignedMapRoot(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.MapRoot, nil
}

func extractMapRoot(signedRoot *trillian.SignedMapRoot, mapPK crypto.PublicKey, verify bool) (*types.MapRootV1, error) {
	if verify {
		return tcrypto.VerifySignedMapRoot(mapPK, 5, signedRoot)
	} else {
		var root types.MapRootV1
		err := root.UnmarshalBinary(signedRoot.MapRoot)
		return &root, err
	}
}
