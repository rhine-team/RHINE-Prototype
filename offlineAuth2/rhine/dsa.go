package rhine

import (
	"github.com/cbergoon/merkletree"
	"time"
)

// Delegation Status Accumulator
type DSA struct {
	zone     string
	alv      AuthorityLevel
	exp      time.Time
	cert     []byte
	acc      merkletree.MerkleTree
	subzones []DSLeafContent
}

type DAcc struct {
	zone     string
	roothash []byte
}

type DSum struct {
	dacc DAcc
	alv  AuthorityLevel
	cert []byte // hash of TBSRc_zone
	exp  time.Time
}

func (dsa DSA) GetDAcc() DAcc {
	return DAcc{
		zone:     dsa.zone,
		roothash: dsa.acc.Root.Hash,
	}
}

func (dsa DSA) GetDSum() DSum {
	return DSum{
		dacc: dsa.GetDAcc(),
		alv:  dsa.alv,
		cert: dsa.cert,
		exp:  dsa.exp,
	}
}
