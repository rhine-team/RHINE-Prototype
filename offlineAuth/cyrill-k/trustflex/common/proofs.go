// Trillian proofs' definitions

package common

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"github.com/google/trillian"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/maphasher"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"time"
)

// Proof defines both a PoA and a Map PoP
type Proof struct {
	MapID     int64                      `json:"map_id"`
	Proof     *trillian.MapLeafInclusion `json:"proof"`
	Timestamp int64                      `json:"timestamp"`
	Signature Signature                  `json:"signature"`
}

func (p *Proof) VerifyProof(root *types.MapRootV1) error {
	return merkle.VerifyMapInclusionProof(p.MapID, p.Proof.Leaf, root.RootHash, p.Proof.Inclusion, maphasher.Default)
}

// Returned by ILSes in GetPoA
type PoAResp struct {
	PoA      Proof               `json:"poa"`
	MultiSMR *MultiSignedMapRoot `json:"msmr"`
}

// PoC from Trillian Log
type PoC struct {
	Proof     *trillian.Proof `json:"proof"`
	Timestamp int64           `json:"timestamp"`
	Signature Signature       `json:"signature"`
}

func (poc *PoC) VerifyProof(first, second uint64, firstHash, secondHash string) error {
	prevHash, err := base64.StdEncoding.DecodeString(firstHash)
	if err != nil {
		return fmt.Errorf("failed to decode prev hash: %s", err)
	}

	currHash, err := base64.StdEncoding.DecodeString(secondHash)
	if err != nil {
		return fmt.Errorf("failed to decode curr hash: %s", err)
	}

	verifier := merkle.NewLogVerifier(rfc6962.DefaultHasher)
	return verifier.VerifyConsistencyProof(int64(first), int64(second), prevHash, currHash, poc.Proof.Hashes)
}

// Returned by ILSes in GetPoC
type PoCResp struct {
	PoC      PoC                 `json:"poc"`
	MultiSLR *MultiSignedLogRoot `json:"mslr"`
}

func MapLeafInclusionToString(p *trillian.MapLeafInclusion) string {
	var out string
	if len(p.Leaf.LeafValue) == 0 {
		out += "<PoA "
	} else {
		out += "<PoP "
	}
	ctr := 0
	var i []byte
	for _, i = range p.Inclusion {
		if len(i) == 0 {
			ctr += 1
			continue
		} else {
			if ctr != 0 {
				if out != "" {
					out += ", "
				}
				out += "[]x" + fmt.Sprintf("%d", ctr)
				ctr = 0
			}
			if out != "" {
				out += ", "
			}
			out += fmt.Sprintf("%x", i)
		}
	}
	if ctr != 0 {
		if out != "" {
			out += ", "
		}
		out += "nil x" + fmt.Sprintf("%d", ctr)
		ctr = 0
	}
	return out + ">"
}

func MapRootV1ToString(p *types.MapRootV1) string {
	return fmt.Sprintf("<MapRootV1 hash=%x, timestamp=%s, revision=%d>", p.RootHash, time.Unix(0, int64(p.TimestampNanos)), p.Revision)
}

type signedMapRootDataType struct {
	MapRoot   []byte
	Signature []byte
}

func MarshalSignedMapRoot(p *trillian.SignedMapRoot) ([]byte, error) {
	return asn1.Marshal(*p)
}

func UnmarshalSignedMapRoot(data []byte, p *trillian.SignedMapRoot) error {
	_, err := asn1.Unmarshal(data, p)
	return err
}
