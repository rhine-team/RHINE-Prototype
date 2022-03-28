package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/rhine-team/RHINE-Prototype/child"
	"github.com/rhine-team/RHINE-Prototype/common"
	"github.com/spf13/cobra"
	"log"
)

var privKeyType string
var privKeyRSA *rsa.PrivateKey
var privKeyEd25519 ed25519.PrivateKey
var privKey interface{}
var newprivKey interface{}
var outputPath string
var zone string
var CA string
var CAAddress string
var CheckerAddress string
var Cert *x509.Certificate

var rootCmd = &cobra.Command{
	Use:   "run_child",
	Short: "Child Zone Manager for Rains Delegation Service",
	Long:  "Child Zone Manager for Rains Delegation Service: Creates CSRs for NewDlg requests and runs ReNewDlg requests for existing certificates",
}

var NewDlgCmd = &cobra.Command{
	Example: "./run_child NewDlg Ed25519 path/to/key/example.key",
	Use:     "NewDlg [PrivateKey Type] [PrivateKey Path]",
	Short:   "Create CSR for a New Delegation",
	Long:    "PrivateKey Type has to be \"RSA\" or \"Ed25519\"",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 2 {
			var err error
			switch args[0] {
			case "RSA":
				privKey, err = common.LoadRSAPrivateKeyPEM(args[1])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			case "Ed25519":
				privKey, err = common.LoadPrivateKeyEd25519(args[1])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			default:
				log.Fatalf("Unsupported key type: %s (must be RSA or Ed25519)", args[0])
			}
		} else if len(args) == 1 {
			switch args[0] {
			case "RSA":
				privKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			case "Ed25519":
				_, privKey, _ = ed25519.GenerateKey(rand.Reader)
				//TODO save keys
			default:
				log.Fatalf("Unsupported key type: %s (must be RSA or Ed25519)", args[0])
			}
		} else {
			cmd.Help()
			return
		}

		csrbytes, err := child.CreateCSR(zone, CA, privKey)
		if err != nil {
			log.Fatal("Error creating CSR: ", err)
		}

		var fileName string
		parsedcsr, _ := x509.ParseCertificateRequest(csrbytes)
		if parsedcsr != nil {
			fileName = parsedcsr.DNSNames[0] + "_Csr.pem"
		}

		var outDir string

		if outputPath[len(outputPath)-1:] == "/" {
			outDir = outputPath + fileName
		} else {
			outDir = outputPath + "/" + fileName
		}

		err = common.StoreCertificateRequestPEM(outDir, csrbytes)
		if err != nil {
			log.Fatal("Error storing CSR: ", err)
		}

		log.Println("CSR for NewDlg created")
	},
}

var ReNewDlgCmd = &cobra.Command{
	Use:   "ReNewDlg [PrivateKey Type] [PrivateKey Path] [Cert Path]",
	Short: "Renew an existing Certificate you control",
	Long:  "PrivateKey Type has to be \"RSA\" or \"Ed25519\"",
	Args:  nil,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 3 {
			var err error
			switch args[0] {
			case "RSA":
				privKey, err = common.LoadRSAPrivateKeyPEM(args[1])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			case "Ed25519":
				privKey, err = common.LoadPrivateKeyEd25519(args[1])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			default:
				log.Fatalf("Unsupported key type: %s (must be RSA or Ed25519)", args[0])
			}

			Cert, err = common.LoadCertificatePEM(args[2])
			if err != nil {
				log.Fatal(err)
			}

		} else {
			cmd.Help()
			return
		}

		certbytes, err := child.ReNewDlg(Cert, privKey, CAAddress, CheckerAddress)
		if err != nil {
			log.Fatal(err)
		}

		var fileName string
		parsedcsr, _ := x509.ParseCertificate(certbytes)
		if parsedcsr != nil {
			fileName = parsedcsr.DNSNames[0] + "_Cert_New.pem"
		}

		var outDir string

		if outputPath[len(outputPath)-1:] == "/" {
			outDir = outputPath + fileName
		} else {
			outDir = outputPath + "/" + fileName
		}

		common.StoreCertificatePEM(outDir, certbytes)

		log.Println("Re-Newed Certificate stored")

		return
	},
}

var KeyChangeDlgCmd = &cobra.Command{
	Use:   "KeyChangeDlg [PrivateKey Type] [PrivateKey Path] [NewPrivateKey Type] [NewPrivateKey Path] [Cert Path] ",
	Short: "Renew an existing Certificate you control and change keys",
	Long:  "PrivateKey Type has to be \"RSA\" or \"Ed25519\"",
	Args:  nil,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 5 {
			var err error
			switch args[0] {
			case "RSA":
				privKey, err = common.LoadRSAPrivateKeyPEM(args[1])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			case "Ed25519":
				privKey, err = common.LoadPrivateKeyEd25519(args[1])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			default:
				log.Fatalf("Unsupported key type: %s (must be RSA or Ed25519)", args[0])
			}

			switch args[2] {
			case "RSA":
				newprivKey, err = common.LoadRSAPrivateKeyPEM(args[3])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			case "Ed25519":
				newprivKey, err = common.LoadPrivateKeyEd25519(args[3])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			default:
				log.Fatalf("Unsupported new key type: %s (must be RSA or Ed25519)", args[2])
			}

			Cert, err = common.LoadCertificatePEM(args[4])
			if err != nil {
				log.Fatal(err)
			}

		} else {
			cmd.Help()
			return
		}

		certbytes, err := child.KeyChangeDlg(Cert, privKey, newprivKey, CAAddress, CheckerAddress)
		if err != nil {
			log.Fatal(err)
		}

		var fileName string
		parsedcsr, _ := x509.ParseCertificate(certbytes)
		if parsedcsr != nil {
			fileName = parsedcsr.DNSNames[0] + "_Cert_NewKey.pem"
		}

		var outDir string

		if outputPath[len(outputPath)-1:] == "/" {
			outDir = outputPath + fileName
		} else {
			outDir = outputPath + "/" + fileName
		}

		common.StoreCertificatePEM(outDir, certbytes)

		log.Println("Re-Newed Certificate stored")

		return
	},
}

var RevokeDlgCmd = &cobra.Command{
	Use:   "RevokeDlg [PrivateKey Type] [PrivateKey Path] [Cert Path]",
	Short: "Revoke an existing Certificate you control",
	Long:  "PrivateKey Type has to be \"RSA\" or \"Ed25519\"",
	Args:  nil,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 3 {
			var err error
			switch args[0] {
			case "RSA":
				privKey, err = common.LoadRSAPrivateKeyPEM(args[1])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			case "Ed25519":
				privKey, err = common.LoadPrivateKeyEd25519(args[1])
				if err != nil {
					log.Fatal("Error loading private key: ", err)
				}
			default:
				log.Fatalf("Unsupported key type: %s (must be RSA or Ed25519)", args[0])
			}

			Cert, err = common.LoadCertificatePEM(args[2])
			if err != nil {
				log.Fatal(err)
			}

		} else {
			cmd.Help()
			return
		}

		err := child.RevokeDlg(Cert, privKey, CheckerAddress)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Certificate Revoked")

		return
	},
}

func init() {

	NewDlgCmd.Flags().StringVar(&outputPath, "out", "./", "Output Folder")
	NewDlgCmd.Flags().StringVar(&zone, "zone", "", "Zone for Certificate")
	NewDlgCmd.Flags().StringVar(&CA, "CA", "Example RAINS CA", "CA Name")
	NewDlgCmd.MarkFlagDirname("out")
	NewDlgCmd.MarkFlagRequired("zone")

	ReNewDlgCmd.Flags().StringVar(&outputPath, "out", "./", "Output Folder")
	ReNewDlgCmd.Flags().StringVar(&CA, "CA", "Same as existing Cert", "CA Name")
	ReNewDlgCmd.MarkFlagDirname("out")
	ReNewDlgCmd.Flags().StringVar(&CAAddress, "CaAddr", "localhost:10000", "CA Address")
	ReNewDlgCmd.Flags().StringVar(&CheckerAddress, "CheckerAddr", "localhost:10001", "Checker Address")

	KeyChangeDlgCmd.Flags().StringVar(&outputPath, "out", "./", "Output Folder")
	KeyChangeDlgCmd.Flags().StringVar(&CA, "CA", "Same as existing Cert", "CA Name")
	KeyChangeDlgCmd.MarkFlagDirname("out")
	KeyChangeDlgCmd.Flags().StringVar(&CAAddress, "CaAddr", "localhost:10000", "CA Address")
	KeyChangeDlgCmd.Flags().StringVar(&CheckerAddress, "CheckerAddr", "localhost:10001", "Checker Address")

	RevokeDlgCmd.Flags().StringVar(&CheckerAddress, "CheckerAddr", "localhost:10001", "Checker Address")

}
func main() {
	rootCmd.AddCommand(NewDlgCmd)
	rootCmd.AddCommand(ReNewDlgCmd)
	rootCmd.AddCommand(KeyChangeDlgCmd)
	rootCmd.AddCommand(RevokeDlgCmd)
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
	return

}


