package rhine

import (
	"errors"
	"strings"
)

type LogManager struct {
	log      Log
	privkey  any
	dsa      DSA
	subzones []DSLeafContent
}

// create dpss from DSA

func (lm LogManager) GetInclusionProof(label string) (merklepath [][]byte, index []int64, err error) {

	for _, leaf := range lm.subzones {
		if leaf.start.zone == label || leaf.end.zone == label {
			merklepath, index, err = lm.dsa.acc.GetMerklePath(leaf)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, errors.New("label not found")
}

func (lm LogManager) GetAbsenceProof(label string) (merklepath [][]byte, index []int64, err error) {

	for _, leaf := range lm.subzones {
		if strings.Compare(leaf.start.zone, label) == -1 && strings.Compare(leaf.end.zone, label) == 1 {
			merklepath, index, err = lm.dsa.acc.GetMerklePath(leaf)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, errors.New("label not found")
}
