package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/keyManager"
)

func main() {
	fmt.Println("INSTRUCTIONS: ./certGen [KeyType] [PrivateKeyPath] [CertificatePath]\tKeyType = RSA or Ed25519\tPrivateKeyPath = e.g keys/private.pem\tCertificatePath = e.g certs/cert.pem")
	if len(os.Args) != 4 {
		log.Fatal("Not enough arguments")
	}

	if os.Args[1] != "RSA" && os.Args[1] != "Ed25519" {
		log.Fatal("Unsupported Algorithm")
	}

	err := keyManager.CreateSelfSignedCACertificate(os.Args[1], os.Args[2], os.Args[3])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Certificate stored")

}
