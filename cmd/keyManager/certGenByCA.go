package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rhine-team/RHINE-Prototype/internal/keyManager"
)

// This script creates a certificate for the pubkey of the given PrivateKey signed by some given CAKey
func main() {
	fmt.Println("INSTRUCTIONS: ./certGen [KeyType] [PrivateKeyPath] [CAKeyPath] [CACertPath] [CertificatePath] [Name]\tKeyType = RSA or Ed25519")
	if len(os.Args) != 7 {
		log.Fatal("Not enough arguments")
	}

	if os.Args[1] != "RSA" && os.Args[1] != "Ed25519" {
		log.Fatal("Unsupported Algorithm")
	}

	err := keyManager.CreateCertificateSignedByCA(os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Certificate created and stored")

}
