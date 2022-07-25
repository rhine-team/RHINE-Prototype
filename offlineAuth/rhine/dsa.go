package rhine

import (
	//"sort"
	"crypto/sha256"
	"time"

	"github.com/cbergoon/merkletree"
)

// Delegation Status Accumulator
type DSA struct {
	zone     string
	alv      AuthorityLevel
	exp      time.Time
	cert     []byte
	acc      *merkletree.MerkleTree
	subzones []DSLeafContent
}

type DAcc struct {
	Zone     string
	Roothash []byte
}

type DSum struct {
	Dacc DAcc
	Alv  AuthorityLevel
	Cert []byte // hash of TBSRc_zone
	Exp  time.Time
}

func (dsa *DSA) GetDAcc() DAcc {
	return DAcc{
		Zone:     dsa.zone,
		Roothash: dsa.acc.Root.Hash,
	}
}

func (dsa *DSA) GetDSum() DSum {
	return DSum{
		Dacc: dsa.GetDAcc(),
		Alv:  dsa.alv,
		Cert: dsa.cert,
		Exp:  dsa.exp,
	}
}

func (d *DSum) GetDSumToBytes() ([]byte, error) {
	hasher := sha256.New()

	hasher.Write([]byte(d.Dacc.Zone))
	hasher.Write(d.Dacc.Roothash)
	hasher.Write([]byte{byte(d.Alv)})
	hasher.Write(d.Cert)

	// expiration time
	if timeBinary, err := d.Exp.MarshalBinary(); err != nil {
		return nil, err
	} else {
		hasher.Write(timeBinary)
	}

	return hasher.Sum(nil), nil
}

/*
func (dsa *DSA) BuildDSLeafOrdered(sliceLeafs []DSLeafZone) {
	// We sort the leafs first
	sort.Slice(sliceLeafs, func(a, b int) bool {
		return sliceLeafs.zone[a] < sliceLeafs.zone[b]
	})

	// Generate the double zone leaf structure
	res := []DSLeafContent{}
	for i, v := range sliceLeafs {
		var succ DSLeafZone

		if i == 0 {
			succ =
		} else if i == len(sliceLeafs)-1 {

		} else {

		}
		leafContent := DSLeafContent{}
		res = append(res, )
	}
}
*/
