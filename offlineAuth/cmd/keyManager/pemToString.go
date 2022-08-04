package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
)

func main() {
	fmt.Println("INSTRUCTIONS: ./pemToString [KeyType] [PrivKeyPath] \tKeyType = RSA or Ed25519")

	if len(os.Args) < 3 {
		log.Fatal("Not enough arguments")
	}

	switch os.Args[1] {
	case "Ed25519":
		PrivateKey, err := rhine.LoadPrivateKeyEd25519(os.Args[2])
		if err != nil {
			log.Fatal("Failed loading key")
		}

		res, errk := rhine.PrivateKeyToStringDER(&PrivateKey)
		if errk != nil {
			log.Println(errk)
		}
		fmt.Println("RESULT: ", res)
	case "RSA":
		PrivateKey, err := rhine.LoadRSAPrivateKeyPEM(os.Args[2])
		if err != nil {
			log.Fatal("Failed loading key")
		}
		res, errk := rhine.PrivateKeyToStringDER(PrivateKey)
		if errk != nil {
			log.Println(errk)
		}
		fmt.Println("RESULT: ", res)
	default:
		log.Fatal("Unsupported Algorithm")
	}

}
