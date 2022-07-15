package rhine

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/cbergoon/merkletree"
)

type MPathProofType int
type DSLeafType int

const (
	ProofOfPresence MPathProofType = 0
	ProofOfAbsence  MPathProofType = 1

	SmallestPossibleZone DSLeafType = 0
	ExistingZone         DSLeafType = 1
	GreatestPossibleZone DSLeafType = 2
)

type MPathProof struct {
	Path     [][]byte
	Index    []int64 //Index shows the way from the root to the content, eg. [0,1,0,1,1,...]
	Lcontent DSLeafContent
	Ptype    MPathProofType
}

type DSLeafZone struct {
	Zone     string
	Alv      AuthorityLevel
	ZoneType DSLeafType
}

type DSLeafContent struct {
	Start DSLeafZone
	End   DSLeafZone
}

func (l DSLeafContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	msg := []byte(l.Start.Zone + l.Start.Alv.ToString() + string(l.Start.ZoneType) + l.End.Zone + l.End.Alv.ToString() + string(l.End.ZoneType))
	_, err := h.Write(msg)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (l DSLeafContent) Equals(other merkletree.Content) (bool, error) {
	res := l.Start.Zone == other.(DSLeafContent).Start.Zone && l.Start.Alv == other.(DSLeafContent).Start.Alv && l.End.Zone == other.(DSLeafContent).End.Zone && l.End.Alv == other.(DSLeafContent).End.Alv
	res = res && l.Start.ZoneType == other.(DSLeafContent).Start.ZoneType && l.End.ZoneType == other.(DSLeafContent).End.ZoneType
	return res, nil
}

func GetNegativeInfinityZone() DSLeafZone {
	return DSLeafZone{
		ZoneType: SmallestPossibleZone,
	}
}

func GetPositiveInfinityZone() DSLeafZone {
	return DSLeafZone{
		ZoneType: GreatestPossibleZone,
	}
}

func GetEmptyContent() DSLeafContent {
	res := DSLeafContent{
		Start: GetNegativeInfinityZone(),
		End:   GetPositiveInfinityZone(),
	}
	return res
}

// Adds a new LeafZone to a slice of DSLeafContent in the canonical order and with infinity elements
func InsertNewDSLeafZone(c []DSLeafContent, zone DSLeafZone) []DSLeafContent {
	if len(c) <= 1 {
		// Leafs look like {} or {(-inf, +inf)}
		negativeInfLeaf := DSLeafContent{
			Start: GetNegativeInfinityZone(),
			End:   zone,
		}

		positiveInfLeaf := DSLeafContent{
			Start: zone,
			End:   GetPositiveInfinityZone(),
		}
		c = append(c, negativeInfLeaf)
		c = append(c, positiveInfLeaf)
		return c
	} else {
		// Iterate until we reach the intended place for the new zone
		for i, leafc := range c {
			// Check existing zones
			if zone.Zone < leafc.Start.Zone && leafc.Start.ZoneType == ExistingZone {
				elemGreater := c[i].Start
				c = append(c[:i+1], c[i:]...)
				c[i] = DSLeafContent{
					Start: zone,
					End:   elemGreater,
				}
				// Update "end" in smaller leaf
				c[i-1].End = zone
				break
			}

			// Check if new zone is the largest elements
			if i == len(c)-1 {
				positiveInfLeaf := DSLeafContent{
					Start: zone,
					End:   GetPositiveInfinityZone(),
				}
				c = append(c, positiveInfLeaf)
				// Update the now second-to-last element
				c[len(c)-2].End = zone
			}
		}
		return c
	}
}

// Generate proof of presence for a LeafZone in a DSA
func (d *DSA) GetMPathProofPresence(zname string) (*MPathProof, bool, error) {
	z := DSLeafZone{
		Zone: zname,
	}

	// Find the right DSLeafContent
	// Assumes subzones== internal leaf list
	var c DSLeafContent

	for i, sz := range d.subzones {
		if sz.Start.Zone == z.Zone { //sz.start.alv == z.alv
			c = sz
			break
		}

		if i == len(d.subzones)-1 {
			// Zone z is not in the DSA
			return nil, false, nil
		}
	}

	pa, ind, err := d.acc.GetMerklePath(c)
	if err != nil {
		return nil, false, err
	}

	return &MPathProof{
		Path:     pa,
		Index:    ind,
		Lcontent: c,
		Ptype:    ProofOfPresence,
	}, true, nil
}

// Generate proof of absence for a LeafZone in a DSA
func (d *DSA) GetMPathProofAbsence(zname string) (*MPathProof, bool, error) {
	z := DSLeafZone{
		Zone: zname,
	}

	// Find the right DSLeafContent
	// Assumes subzones== internal leaf list
	var c DSLeafContent

	for _, sz := range d.subzones {
		if sz.Start.Zone == z.Zone { //&& sz.start.alv == z.alv
			// Element is actually present, we return false and no proof
			return nil, false, nil
		}

		largerThanStart := sz.Start.ZoneType == SmallestPossibleZone || (sz.Start.ZoneType == ExistingZone && sz.Start.Zone < z.Zone)
		smallerThanEnd := sz.End.ZoneType == GreatestPossibleZone || (sz.End.ZoneType == ExistingZone && z.Zone < sz.End.Zone)

		if largerThanStart && smallerThanEnd {
			// We have found the bounds for our zone, remember the DSLeafContent
			c = sz
		}
	}

	pa, ind, err := d.acc.GetMerklePath(c)
	if err != nil {
		return nil, false, err
	}

	return &MPathProof{
		Path:     pa,
		Index:    ind,
		Lcontent: c,
		Ptype:    ProofOfAbsence,
	}, true, nil
}

func (p *MPathProof) VerifyMPathProof(roothash []byte, zname string) (bool, error) {
	z := DSLeafZone{
		Zone: zname,
	}

	if p.Ptype == ProofOfPresence {
		//Check if zone is the start zone of the given DSLeafContent
		if !(p.Lcontent.Start.Zone == z.Zone) { //&& p.lcontent.start.alv == z.alv
			return false, nil
		}
	} else if p.Ptype == ProofOfAbsence {
		// Check if zone in range
		sz := &p.Lcontent
		largerThanStart := sz.Start.ZoneType == SmallestPossibleZone || (sz.Start.ZoneType == ExistingZone && sz.Start.Zone < z.Zone)
		smallerThanEnd := sz.End.ZoneType == GreatestPossibleZone || (sz.End.ZoneType == ExistingZone && z.Zone < sz.End.Zone)
		if !(largerThanStart && smallerThanEnd) {
			// z is not in the range given by the proof
			return false, nil
		}
	} else {
		return false, errors.New("Unknown proof type")
	}

	// Now we check if the proof matches the roothash signed by loggers/aggregators
	// (This code is based on a test in cbergoon/merkletree)
	hash, erro := p.Lcontent.CalculateHash()
	if erro != nil {
		return false, erro
	}

	h := sha256.New()
	for k := 0; k < len(p.Path); k++ {
		if p.Index[k] == 1 {
			hash = append(hash, p.Path[k]...)
		} else {
			hash = append(p.Path[k], hash...)
		}
		if _, err := h.Write(hash); err != nil {
			return false, err
		}

		hash = h.Sum(nil)
	}

	// test if the root matches the given root
	return bytes.Compare(roothash, hash) == 0, nil
}
