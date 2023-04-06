package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rhine-team/RHINE-Prototype/internal/keyManager"
)

func main() {
	fmt.Println("INSTRUCTIONS: ./keyGen [KeyType] [OutputPath] [PubKey]\tKeyType = RSA or Ed25519\tOutputPath = e.g keys/private.pem\tPubKey=--pubkey (optional)")

	if len(os.Args) < 3 {
		log.Fatal("Not enough arguments")
	}

	// Decide to also generate a pubkey or not
	genPubkey := len(os.Args) == 4 && os.Args[3] == "--pubkey"

	switch os.Args[1] {
	case "RSA":
		err := keyManager.CreateRSAKey(os.Args[2], genPubkey)
		if err != nil {
			log.Fatal(err)
		}
	case "Ed25519":
		err := keyManager.CreateEd25519Key(os.Args[2], genPubkey)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Unsupported Algorithm")
	}

	fmt.Println("Key stored")

}
