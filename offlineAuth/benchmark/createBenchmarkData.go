package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"crypto/ed25519"
	"crypto/rand"
	mrand "math/rand"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
	"golang.org/x/exp/slices"
)

// This script should be run on the parent server

var zoneFixed = ".benchmark.ch"
var childkeyPrefix = "CHILDPK_"
var parentKeyPrefix = "PARENTSK_"
var parentCertPrefix = "PARENTCERT_"

func main() {
	fmt.Println("The following arguments needed: [ParentDB (1)] [CAKey (2)] [CACert (3)] [NumberParents (4)] [NumberCHildrenPerParent (5)] [ChildKeysOutputPath (6)] [ParenCertOutputPath (7)]")
	// Path must end in a slash

	if len(os.Args) < 8 {
		log.Fatal("Need 8 arguments, not ", os.Args)
	}

	numParents, _ := strconv.Atoi(os.Args[4])
	numChildren, _ := strconv.Atoi(os.Args[5])

	// Open  parent database (should be created if not existing yet)
	db, errdb := badger.Open(badger.DefaultOptions(os.Args[1]))
	if errdb != nil {
		log.Fatal("Badger error: ", errdb)
	}
	defer db.Close()

	// Parse CA priv key
	privKeyCA, errCA := rhine.LoadPrivateKeyEd25519(os.Args[2])
	if errCA != nil {
		log.Fatalf("Could not lead priv CA", errCA)
	}

	// Create a list of parent names
	parentNames := RandomNames(numParents)

	//parentPriv := []*ed25519.PrivateKey{}
	//parentPub := []*ed25519.PublicKey{}
	for i := 0; i < numParents; i++ {
		// Create parent keys
		pbkey, privatekey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("Failed creating ed25519 key")
		}

		// Create Parent certs
		pName := parentNames[i] + zoneFixed
		certbytes, errcert := rhine.CreateCertificateUsingCA(pbkey, privatekey, privKeyCA, os.Args[3], pName)
		if errcert != nil {
			log.Fatalf("Creating parent cert fail:", errcert)
		}

		// Save parent cert
		err = rhine.StoreCertificatePEM(os.Args[7]+"CERT_"+pName+".pem", certbytes)
		if err != nil {
			log.Fatalf("Storing cert fail", err)
		}

		// Save cert and public key to DB
		// Save cert to parent DB
		err = db.Update(func(txn *badger.Txn) error {
			err := txn.Set([]byte(parentCertPrefix+pName), certbytes)
			return err
		})
		if err != nil {
			log.Fatalf("Saving to DB fail", err)
		}
		// Save parent priv key to DB
		err = db.Update(func(txn *badger.Txn) error {
			err := txn.Set([]byte(parentKeyPrefix+pName), privatekey)
			return err
		})
		if err != nil {
			log.Fatalf("Saving parent priv key fail to DB", err)
		}

		// Create children
		childrenNames := RandomNames(numChildren)
		for j := 0; j < numChildren; j++ {
			pbkeyChild, privatekeyChild, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				log.Fatalf("Failed creating ed25519 key for a child")
			}

			cName := childrenNames[j] + "." + pName
			// Save the keys to disk
			err = rhine.StorePublicKeyEd25519(os.Args[6]+cName+"_pub.pem", pbkeyChild)
			if err != nil {
				log.Fatalf("Could not save pk to disk", err)
			}

			err = rhine.StorePrivateKeyEd25519(os.Args[6]+cName+".pem", privatekeyChild)
			if err != nil {
				log.Fatalf("Storing priv key failed ", err)
			}

			// Save pubkey to parent DB
			err = db.Update(func(txn *badger.Txn) error {
				err := txn.Set([]byte(childkeyPrefix+cName), pbkeyChild)
				return err
			})
			if numParents*numChildren%50 == 0 {
				log.Println("Saved ", j, " child data for parent: ", i)
			}

		}

	}

}

func RandomNames(numberNames int) []string {
	reslist := make([]string, numberNames)

	for i := range reslist {
		newName := RandomName()
		// Check if already chosen
		for slices.Contains(reslist, newName) {
			newName = RandomName()
		}
		reslist[i] = newName
	}
	return reslist
}

func RandomName() string {
	lengthName := 15
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	mrand.Seed(time.Now().UnixNano())
	res := make([]rune, lengthName)
	for j := range res {
		random := mrand.Intn(len(chars))
		res[j] = chars[random]
	}
	return string(res)
}
