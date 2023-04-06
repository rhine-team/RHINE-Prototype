package rhine

import (
	"crypto/sha256"
	"errors"
	"log"
	logger "log"
	"time"

	badger "github.com/dgraph-io/badger/v3"
	cmap "github.com/orcaman/concurrent-map/v2"
	//"github.com/rhine-team/RHINE-Prototype/offlineAuth/merkletree"
)

var defaultHashStrat = sha256.New
var CACHE_MAX_SIZE = 200000

type DSALog struct {
	zoneToDSA cmap.ConcurrentMap[*DSA] //map[string]*DSA
	T         uint64
}

func NewDSALog() *DSALog {
	zToDsa := cmap.New[*DSA]()
	dsalog := &DSALog{
		zoneToDSA: zToDsa, //zoneToDSA: make(map[string]*DSA),
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
	log, pres := lm.zoneToDSA.Get(PZone) //lm.zoneToDSA[PZone]

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
				dsares := &DSA{}
				errdeserial := DeserializeCBOR(val, dsares)

				if errdeserial != nil {
					return errdeserial
				}

				log = dsares

				// Relink Merkle Tree
				log.Acc.RestoreAfterMarshalling()
				//log.Acc, _ = NewTree(log.Subzones)
				//log.Acc.RestoreAfterMarshalling()

				// Add to cache
				lm.zoneToDSA.Set(PZone, log)

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

func (dl *DSALog) AddDelegationStatus(pZone string, pAlv AuthorityLevel, pCert []byte, exp time.Time, cZone string, cAlv AuthorityLevel, cCert []byte, db *badger.DB) error {
	logd := dl.zoneToDSA

	newDelegZone := DSLeafZone{
		Zone:     cZone,
		Alv:      cAlv,
		ZoneType: ExistingZone,
	}

	// Check if cache is full
	if dl.zoneToDSA.Count() > CACHE_MAX_SIZE {
		// Delete an entry from cache
		// TODO a better replacement scheme than this
		var key string
		for k, _ := range dl.zoneToDSA {
			key = string(k)
			break
		}

		logd.Remove(key) //delete(d.zoneToDSA, key)
	}

	// Check if DSA for parent zone exists

	dsa, prs := logd.Get(pZone) //:= d.zoneToDSA[pZone]
	if !prs {
		content := []DSLeafContent{}
		content = InsertNewDSLeafZone(content, newDelegZone)

		newTree, err := NewTree(content)
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
		logd.Set(pZone, dsa) //d.zoneToDSA[pZone] = dsa
	} else {
		// A DSA for the parent zone exists
		dsa.Subzones = InsertNewDSLeafZone(dsa.Subzones, newDelegZone)

		if dsa.Acc == nil {
			newTree, err := NewTree(dsa.Subzones)
			if err != nil {
				return err
			}
			dsa.Acc = newTree
		}

		err := dsa.Acc.RebuildTreeWith(dsa.Subzones)
		if err != nil {
			return err
		}
	}

	// The new delegation has been added to cache, now add it to the DB

	// We have to remove cyclical links
	dsa.Acc.PrepareForMarshalling()
	dsabytes, errser := SerializeCBOR(*dsa)
	dsa.Acc.RestoreAfterMarshalling()
	if errser != nil {
		log.Println("The following error while serializing: ", errser)
		return errser
	}

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
	newTreeChild, errtree := NewTree(content)
	if errtree != nil {
		return errtree
	}

	dsanew := &DSA{
		Zone: cZone,
		Alv:  cAlv,
		//Exp:      exp,
		Cert:     cCert,
		Acc:      newTreeChild,
		Subzones: content,
	}
	//TODO
	//d.zoneToDSA[cZone] = dsanew

	// The new DSA of the child can be added
	dsanew.Acc.PrepareForMarshalling()
	dsabytes, errserial := SerializeCBOR(*dsanew)
	dsanew.Acc.RestoreAfterMarshalling()
	if errserial != nil {
		log.Println("DSALog: Error serializing new child DSA", errserial)
		return errserial
	}

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

func (dl *DSALog) AddDelegationStatusShort(pZone string, pAlv AuthorityLevel, pCert []byte, exp time.Time, cZone string, cAlv AuthorityLevel, cCert []byte, db *badger.DB) error {
	logd := dl.zoneToDSA

	// Check if cache is full
	if dl.zoneToDSA.Count() > CACHE_MAX_SIZE {
		// Delete an entry from cache
		// TODO a better replacement scheme than this
		var key string
		for k, _ := range dl.zoneToDSA {
			key = string(k)
			break
		}

		logd.Remove(key) //delete(d.zoneToDSA, key)
	}

	// The child itself now gets a DSA
	// We make an empty tree with only the ({negInf, posInf}) element
	content := []DSLeafContent{}

	emptyTreeCont := DSLeafContent{
		Start: GetNegativeInfinityZone(),
		End:   GetPositiveInfinityZone(),
	}

	content = append(content, emptyTreeCont)
	newTreeChild, errtree := NewTree(content)
	if errtree != nil {
		return errtree
	}

	dsanew := &DSA{
		Zone: cZone,
		Alv:  cAlv,
		//Exp:      exp,
		Cert:     cCert,
		Acc:      newTreeChild,
		Subzones: content,
	}
	//TODO
	//d.zoneToDSA[cZone] = dsanew

	// The new DSA of the child can be added
	dsanew.Acc.PrepareForMarshalling()
	dsabytes, errserial := SerializeCBOR(*dsanew)
	dsanew.Acc.RestoreAfterMarshalling()
	if errserial != nil {
		log.Println("DSALog: Error serializing new child DSA", errserial)
		return errserial
	}

	err := db.Update(func(txn *badger.Txn) error {

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
