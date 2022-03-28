package main

import (
	"fmt"
	"github.com/rhine-team/RHINE-Prototype/keyManager"
	"log"
	"os"
)

func main() {
	fmt.Println("INSTRUCTIONS: ./keyGen [KeyType] [OutputPath]\tKeyType = RSA or Ed25519\tOutputPath = e.g keys/private.pem")

	if len(os.Args) != 3 {
		log.Fatal("Not enough arguments")
	}

	switch os.Args[1] {
	case "RSA":
		err := keyManager.CreateRSAKey(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
	case "Ed25519":
		err := keyManager.CreateEd25519Key(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("Unsupported Algorithm")
	}

	fmt.Println("Key stored")

}
