package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rhine-team/RHINE-Prototype/internal/keyManager"
)

func main() {
	fmt.Println("INSTRUCTIONS: ./keyGen [KeyType] [PrivKeyPath] [OutputPath] \tKeyType = RSA or Ed25519")

	if len(os.Args) < 4 {
		log.Fatal("Not enough arguments")
	}

	switch os.Args[1] {
	case "RSA":
		err := keyManager.DerivePubKeyRSA(os.Args[2], os.Args[3])
		if err != nil {
			log.Fatal(err)
		}
	case "Ed25519":
		err := keyManager.DerivePubKeyEd25519(os.Args[2], os.Args[3])
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Unsupported Algorithm")
	}

	fmt.Println("Key stored")

}
