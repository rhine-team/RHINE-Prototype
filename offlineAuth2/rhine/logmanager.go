package rhine

import (
	"errors"
	"strings"
)

type LogManager struct {
	log     Log
	privkey any
	logs    map[string]DSA
	T       uint64
}

func (lm LogManager) DSProofRet(PZone string, CZone string, ptype MPathProofType) Dsp {
	log := lm.logs[PZone]

	dsp := Dsp{
		dsum:   log.GetDSum(),
		epochT: lm.T,
		sig:    RhineSig{},
		proof:  MPathProof{},
	}

	dsp.Sign(lm.privkey)

	var path [][]byte
	switch ptype {
	case ProofOfPresence:
		path, _, _ = lm.GetInclusionProof(PZone, CZone)
	case ProofOfAbsence:
		path, _, _ = lm.GetAbsenceProof(PZone, CZone)
	}

	dsp.proof = MPathProof{
		path:  path,
		ptype: ptype,
	}

	return dsp
}

func (lm LogManager) GetInclusionProof(zone string, label string) (merklepath [][]byte, index []int64, err error) {

	log := lm.logs[zone]

	for _, leaf := range log.subzones {
		if leaf.start.zone == label || leaf.end.zone == label {
			merklepath, index, err = log.acc.GetMerklePath(leaf)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, errors.New("label not found")
}

func (lm LogManager) GetAbsenceProof(zone string, label string) (merklepath [][]byte, index []int64, err error) {

	log := lm.logs[zone]

	for _, leaf := range log.subzones {
		if strings.Compare(leaf.start.zone, label) == -1 && strings.Compare(leaf.end.zone, label) == 1 {
			merklepath, index, err = log.acc.GetMerklePath(leaf)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, errors.New("label not found")
}
