package rhine

import (
	"crypto/sha256"
	"time"
	//"github.com/rhine-team/RHINE-Prototype/offlineAuth/merkletree"
)

// Delegation Status Accumulator
type DSA struct {
	Zone     string
	Alv      AuthorityLevel
	Exp      time.Time
	Cert     []byte
	Acc      *MerkleTree
	Subzones []DSLeafContent

	Signature []byte
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
		Zone:     dsa.Zone,
		Roothash: dsa.Acc.Root.Hash,
	}
}

func (dsa *DSA) GetDSum() DSum {
	return DSum{
		Dacc: dsa.GetDAcc(),
		Alv:  dsa.Alv,
		Cert: dsa.Cert,
		Exp:  dsa.Exp,
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
