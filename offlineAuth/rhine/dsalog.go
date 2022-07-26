package rhine

import (
	//"crypto/sha256"
	"errors"
	logger "log"
	"time"

	"github.com/cbergoon/merkletree"
)

type DSALog struct {
	zoneToDSA map[string]*DSA
	T         uint64
}

// TODO Errors?
func NewDSALog() *DSALog {
	dsalog := &DSALog{
		//privKey:   priv,
		zoneToDSA: make(map[string]*DSA),
	}
	return dsalog
}

func (lm *DSALog) DSProofRet(PZone string, CZone string, ptype MPathProofType) (Dsp, error) {
	log, pres := lm.zoneToDSA[PZone]

	// Not present, construct empty tree
	if !pres {
		newC := GetEmptyContent()
		cont := []DSLeafContent{}
		co := []merkletree.Content{}
		cont = append(cont, newC)
		co = append(co, newC)

		newTree, err := merkletree.NewTree(co)
		if err != nil {
			logger.Println("Merkletree creation failed")
			return Dsp{}, err
		}

		lm.zoneToDSA[PZone] = &DSA{
			zone: PZone,
			//TODO only for testing!
			alv: AuthorityLevel(0b0001),
			//exp:      time.Time
			cert:     []byte{},
			acc:      newTree,
			subzones: cont,
		}
		log = lm.zoneToDSA[PZone]
	}

	dsp := Dsp{
		Dsum:   log.GetDSum(),
		EpochT: lm.T,
		Sig:    RhineSig{},
		Proof:  MPathProof{},
	}

	var path *MPathProof
	var presBool bool
	var err error
	switch ptype {
	case ProofOfPresence:
		path, presBool, err = log.GetMPathProofPresence(CZone)
	case ProofOfAbsence:
		path, presBool, err = log.GetMPathProofAbsence(CZone)
	}

	if err != nil {
		logger.Println("Error while getting proof", err)
		return dsp, err
	}

	if !presBool {
		logger.Println("Claim of absence/presence wrong!")
		return dsp, errors.New("Claim of absence/presence wrong!")
	}

	if path != nil {
		logger.Printf("Print our Proof %+v", path)
	}

	dsp.Proof = *path

	return dsp, nil
}

func (d *DSALog) AddDelegationStatus(pZone string, pAlv AuthorityLevel, pCert []byte, exp time.Time, cZone string, cAlv AuthorityLevel) error {

	newDelegZone := DSLeafZone{
		Zone:     cZone,
		Alv:      cAlv,
		ZoneType: ExistingZone,
	}

	// Check if DSA for parent zone exists
	dsa, prs := d.zoneToDSA[pZone]
	if !prs {
		/*
		   // Absent, so create a new DSA
		   // We create two leafs, representing negative and positive infinity
		   newDelegZone := DSLeafZone{
		           zone:  cZone,
		           alv:  cAlv,
		           zoneType: ExistingZone,
		   }

		   negativeInfLeaf := DSLeafContent{
		           start: GetNegativeInfinityZone(),
		           end: newDelegZone,
		   }

		   positiveInfLeaf := DSLeafContent{
		           start: newDelegZone,
		           end: GetPositiveInfinityZone(),
		   }
		   content := []DSLeafContent{negativeInfLeaf, positiveInfLeaf}
		*/

		//content := []DSLeafContent{}
		content := []DSLeafContent{}
		content = InsertNewDSLeafZone(content, newDelegZone)
		//TODO must be a better way
		cont := []merkletree.Content{}

		for _, co := range content {
			cont = append(cont, co)
		}

		newTree, err := merkletree.NewTree(cont)
		if err != nil {
			return err
		}

		d.zoneToDSA[pZone] = &DSA{
			zone:     pZone,
			alv:      pAlv,
			exp:      exp,
			cert:     pCert,
			acc:      newTree,
			subzones: content,
		}
	} else {
		// A DSA for the parent zone exists
		dsa.subzones = InsertNewDSLeafZone(dsa.subzones, newDelegZone)

		//TODO must be a better way
		cont := []merkletree.Content{}

		for _, co := range dsa.subzones {
			cont = append(cont, co)
		}
		err := dsa.acc.RebuildTreeWith(cont)
		if err != nil {
			return err
		}
	}
	return nil
}
