package main

import (
	"crypto/x509"
	"github.com/rhine-team/RHINE-Prototype/common"
	"github.com/rhine-team/RHINE-Prototype/parent"
	"github.com/spf13/cobra"
	"log"
)

var config parent.Config
var csrPath string
var IndependentSubZone bool

var rootCmd = &cobra.Command{
	Use:   "run_parent [Config Path]",
	Short: "Parent Zone Manager for Rains Delegation Service",
	Long:  "Parent Zone Manager for Rains Delegation Service: Runs NewDlg request for CSR",
	Args:  nil,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		var configpath string
		if len(args) == 1 {
			configpath = args[0]
		} else {
			configpath = "config/parentconfig.conf"
		}
		config, err = parent.LoadConfig(configpath)
		if err != nil {
			cmd.Help()
			log.Fatalf("Was not able to load config file: %v", err)
		}
	},
}

func init() {
	rootCmd.Flags().StringVar(&csrPath, "NewDlg", "", "CSR Path")
	rootCmd.Flags().BoolVar(&IndependentSubZone, "IndSubZone", true, "Independent Subzone Flag")
}
func main() {

	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
	par := parent.NewParent(config)

	log.Printf("Parent Created: %#v\n", par)

	if rootCmd.Flag("NewDlg").Changed {
		csrbytes, err := common.LoadCertificateRequestPEM(csrPath)
		if err != nil {
			log.Fatal("Could not load CSR from "+csrPath+" ", err)
		}

		certbytes, err := par.NewDlg(csrbytes, IndependentSubZone)
		if err != nil {
			log.Fatal(err)
		}
		//fmt.Println(certbytes)
		var fileName string
		parsedcert, _ := x509.ParseCertificate(certbytes)
		if parsedcert != nil {
			fileName = parsedcert.DNSNames[0] + "_Cert.pem"
		}

		var outDir string

		if par.OutputDir[len(par.OutputDir)-1:] == "/" {
			outDir = par.OutputDir + fileName
		} else {
			outDir = par.OutputDir + "/" + fileName
		}

		common.StoreCertificatePEM(outDir, certbytes)
		log.Println("Parent: Certificate Stored")

		return
	}

	log.Println("No Flags set:")
	rootCmd.Help()

}
