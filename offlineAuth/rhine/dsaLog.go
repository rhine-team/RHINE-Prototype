package rhine

import (
	"crypto/sha256"
	"errors"
	"log"
	logger "log"
	"time"

	"github.com/RubFischer/merkletree"
	badger "github.com/dgraph-io/badger/v3"
)

var defaultHashStrat = sha256.New
var CACHE_MAX_SIZE = 10000

type DSALog struct {
	zoneToDSA map[string]*DSA
	T         uint64
}

func NewDSALog() *DSALog {
	dsalog := &DSALog{
		zoneToDSA: make(map[string]*DSA),
	}
	return dsalog
}

func (dl *DSALog) DSRetrieve(zones []string, privkey any, db *badger.DB) ([][]byte, [][]byte, error) {
	res := [][]byte{}
	resSignatures := [][]byte{}

	// TODO Improve
	if len(zones) == 0 {
		// Check badger DB
		err := db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchSize = 10
			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Rewind(); it.Valid(); it.Next() {
				item := it.Item()
				//k := item.Key()
				errview := item.Value(func(val []byte) error {
					// This func with val would only be called if item.Value encounters no error.
					resT := append([]byte{}, val...)
					res = append(res, resT)

					return nil
				})
				if errview != nil {
					return errview
				}
			}

			return nil
		})
		if err != nil {
			return res, resSignatures, err
		}

		// Create signatures
		rsig := &RhineSig{Data: res[len(res)-1]}
		rsig.Sign(privkey)
		resSignatures = append(resSignatures, rsig.Signature)

	}

	return res, resSignatures, nil

}

// db is the Badger DB  storing DSAs
// This function will check cache (our map stored in the AggManager or LoggerManager) first, then search for the DSA in the data base
func (lm *DSALog) DSProofRet(PZone string, CZone string, ptype MPathProofType, db *badger.DB) (Dsp, error) {
	var err error

	// Check cache
	log, pres := lm.zoneToDSA[PZone]

	//logger.Println("how it looks ", log)

	if !pres {
		// Check badger DB
		err = db.View(func(txn *badger.Txn) error {
			var errview error
			item, errview := txn.Get([]byte(PZone))

			if errview != nil {
				return errview
			}

			errview = item.Value(func(val []byte) error {
				// This func with val would only be called if item.Value encounters no error.

				// Parse the value
				// Values are serialized DSA structs
				dsares, errdeserial := DeserializeStructure[DSA](val)

				if errdeserial != nil {
					return errdeserial
				}

				log = &dsares

				// Rebuild Merkle Tree
				log.Acc, _ = merkletree.NewTree(DSAContentToGeneric(log.Subzones))

				return nil
			})
			if errview != nil {
				return errview
			}

			return nil
		})
	}

	// Not present in cache and not present in data base
	if !pres && err != nil {
		return Dsp{}, errors.New("Parent zone is not in Delegation Transperancy!")

		/*
			// NOTE: This should really only be for ROOT
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
				Zone: PZone,
				//TODO only for testing!
				Alv: AuthorityLevel(0b0001),
				//exp:      time.Time
				Cert:     []byte{},
				Acc:      newTree,
				Subzones: cont,
				Signature: []byte,
			}
			log = lm.zoneToDSA[PZone]
		*/
	}

	dsp := Dsp{
		Dsum:   log.GetDSum(),
		EpochT: lm.T,
		Sig:    RhineSig{},
		Proof:  MPathProof{},
	}

	var path *MPathProof
	var presBool bool
	//var err error
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

	logger.Println("Ready to return a dsp", dsp)

	return dsp, nil
}

func (d *DSALog) AddDelegationStatus(pZone string, pAlv AuthorityLevel, pCert []byte, exp time.Time, cZone string, cAlv AuthorityLevel, cCert []byte, db *badger.DB) error {

	newDelegZone := DSLeafZone{
		Zone:     cZone,
		Alv:      cAlv,
		ZoneType: ExistingZone,
	}

	// Check if cache is full
	if len(d.zoneToDSA) > CACHE_MAX_SIZE {
		// Delete an entry from cache
		// TODO a better replacement scheme than this
		var key string
		for k, _ := range d.zoneToDSA {
			key = k
			break
		}
		delete(d.zoneToDSA, key)
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

		dsa = &DSA{
			Zone:     pZone,
			Alv:      pAlv,
			Exp:      exp,
			Cert:     pCert,
			Acc:      newTree,
			Subzones: content,
		}
		d.zoneToDSA[pZone] = dsa
	} else {
		// A DSA for the parent zone exists
		dsa.Subzones = InsertNewDSLeafZone(dsa.Subzones, newDelegZone)

		//TODO must be a better way
		cont := []merkletree.Content{}

		for _, co := range dsa.Subzones {
			cont = append(cont, co)
		}
		err := dsa.Acc.RebuildTreeWith(cont)
		if err != nil {
			return err
		}
	}

	// The new delegation has been added to cache, now add it to the DB

	// We have to clear MT, as circular structs do not work with gob
	tempdsaAcc := dsa.Acc
	dsa.Acc = nil
	dsabytes, _ := SerializeStructure[DSA](*dsa)
	dsa.Acc = tempdsaAcc

	err := db.Update(func(txn *badger.Txn) error {
		err := txn.Set([]byte(pZone), dsabytes)
		return err
	})
	if err != nil {
		log.Println("DSALog: Error saving new delegation to badger DB", err)
		return err
	}

	// The child itself now gets a DSA
	// We make an empty tree with only the ({negInf, posInf}) element
	content := []DSLeafContent{}

	emptyTreeCont := DSLeafContent{
		Start: GetNegativeInfinityZone(),
		End:   GetPositiveInfinityZone(),
	}

	content = append(content, emptyTreeCont)

	dsanew := &DSA{
		Zone: cZone,
		Alv:  cAlv,
		//Exp:      exp,
		Cert:     cCert,
		Acc:      nil,
		Subzones: content,
	}
	d.zoneToDSA[cZone] = dsanew

	// The new DSA of the child can be added
	tempAcc := dsanew.Acc
	dsanew.Acc = nil
	dsabytes, errserial := SerializeStructure[DSA](*dsanew)
	if errserial != nil {
		log.Println("DSALog: Error serializing new child DSA", errserial)
		return errserial
	}
	dsanew.Acc = tempAcc

	err = db.Update(func(txn *badger.Txn) error {

		err := txn.Set([]byte(cZone), dsabytes)
		return err
	})
	if err != nil {
		log.Println("DSALog: Error saving new delegation (child) to badger DB", err)
		return err
	}

	log.Println("DSALog: New delegation added to cache and badger DB")

	return nil
}

func DSAContentToGeneric(dsalist []DSLeafContent) []merkletree.Content {
	cont := []merkletree.Content{}

	for _, co := range dsalist {
		cont = append(cont, co)
	}
	return cont
}
