package main

import (
	"log"
	"net"
	"os"
	"strings"
	"time"

	"path/filepath"

	"github.com/google/certificate-transparency-go/x509"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/aggregator"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/components/aggregator/aggserver"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
	"github.com/spf13/cobra"

	"google.golang.org/grpc"
)

var configPath string
var testParentZone string
var testCertPath string
var parentCertDirectoryPath string

var rootCmd = &cobra.Command{
	Use:   "run_Aggregator",
	Short: "Aggregator server",
	Long:  "Server running an aggregator needed for RHINE",
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}

		// Make a new Agg struct
		aggr := rhine.NewAggManager(cof)

		// Run the Agg
		lis, err := net.Listen("tcp", cof.ServerAddress)
		if err != nil {
			log.Fatalf("Listen failed: %v", err)
		}

		s := grpc.NewServer()
		pf.RegisterAggServiceServer(s, &aggserver.AggServer{AggManager: aggr})

		log.Println("Rhine Aggregator server online at: ", cof.ServerAddress)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Serving failed: %v", err)
		}
	},
}

var WipeDB = &cobra.Command{
	Example: "./run_Aggregator WipeDB",
	Use:     "WipeDB",
	Short:   "Wiped the Aggregator DB",
	Long:    "Deletes everything from the badger DB of the Aggregator",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}
		log.Println("Configuration file parsed.")

		// Make a new Log struct
		aggr := rhine.NewAggManager(cof)

		log.Println("New Aggregator Manager initialized")

		err := aggr.DB.DropAll()
		if err != nil {
			log.Println("Deletions failed!")
		} else {
			log.Println("All badger data has been dropped with succes!")
		}
	},
}

var AddTestDT = &cobra.Command{
	Example: "./run_Aggregator AddTestDT",
	Use:     "AddTestDT --parent=ethz.ch --certPath=data/cert.pem",
	Short:   "Construct DT data structure to conduct a test run for some zone",
	Long:    "Construct DT data structure to conduct a test run for some zone",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}
		log.Println("Configuration file parsed.")

		// Make a new Log struct
		aggr := rhine.NewAggManager(cof)

		log.Println("New Aggregator Manager initialized")

		aL := rhine.AuthorityLevel(0b0001)

		//Load cert
		var cert *x509.Certificate
		if testCertPath != "" {
			var err error
			cert, err = rhine.LoadCertificatePEM(testCertPath)
			if err != nil {
				log.Fatal("Error loading certificate: ", err)
			}
		} else {
			log.Fatal("Must provide a parent cert!")
		}
		pCert := rhine.ExtractTbsRCAndHash(cert, false)
		expirationTime := time.Now().Add(time.Hour * 24 * 180)

		aggr.Dsalog.AddDelegationStatus(testParentZone, aL, pCert, expirationTime, "testzonechild."+testParentZone, rhine.AuthorityLevel(0b0001), []byte{}, aggr.DB)
		log.Println("Added test DSA to Aggregator database")

		/*
			// Test if workes
			dsp, errdsp := aggr.Dsalog.DSProofRet(testParentZone, "testzonechild."+testParentZone, rhine.ProofOfPresence, aggr.DB)
			if errdsp != nil {
				log.Fatalln("Something went wrong! ", errdsp)
			}
			log.Printf("Looks like %+v", dsp)
			boolres, errres := dsp.Proof.VerifyMPathProof(dsp.Dsum.Dacc.Roothash, "testzonechild."+testParentZone)
			log.Println("Res ", boolres, errres)
		*/
	},
}

var AddDTBatch = &cobra.Command{
	Example: "./run_Aggregator AddDTBatch",
	Use:     "AddDTBatch --config=data/configs/AggConfig.json --pCertDir=data/temp/parentcerts",
	Short:   "Construct DT data structure in bulk",
	Long:    "Construct DT data structure in bulk",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}
		log.Println("Configuration file parsed.")

		// Make a new Agg struct
		aggr := rhine.NewAggManager(cof)

		log.Println("New Aggregator Manager initialized")

		aL := rhine.AuthorityLevel(0b0001)

		// Iterate over all cert files in the dir
		filepath.Walk(parentCertDirectoryPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				log.Fatalf("The following error while iterating: ", err.Error())
			}
			// Check if the correct prefix is present
			if strings.HasPrefix(info.Name(), "CERT_") {
				//Load cert
				cert, err := rhine.LoadCertificatePEM(path)
				if err != nil {
					log.Fatal("Error loading certificate: ", err)
				}
				// Add to DB
				pCert := rhine.ExtractTbsRCAndHash(cert, false)
				expirationTime := time.Now().Add(time.Hour * 24 * 180)

				pZoneName := strings.TrimPrefix(info.Name(), "CERT_")
				pZoneName = strings.Replace(pZoneName, ".pem", "", 1)
				aggr.Dsalog.AddDelegationStatus(pZoneName, aL, pCert, expirationTime, "testzonechild."+testParentZone, rhine.AuthorityLevel(0b0001), []byte{}, aggr.DB)

			}
			return nil
		})
	},
}

func init() {
	rootCmd.Flags().StringVar(&configPath, "config", "configs/configAgg.json", "ConfigPath")
	WipeDB.Flags().StringVar(&configPath, "config", "configs/configAgg.json", "ConfigPath")
	AddTestDT.Flags().StringVar(&configPath, "config", "configs/configAgg.json", "ConfigPath")
	AddTestDT.Flags().StringVar(&testParentZone, "parent", "ethz.ch", "ParentZone")
	AddTestDT.Flags().StringVar(&testCertPath, "certPath", "example.pem", "CertificatePath")
	AddDTBatch.Flags().StringVar(&configPath, "config", "configs/configAgg.json", "ConfigPath")
	AddDTBatch.Flags().StringVar(&parentCertDirectoryPath, "pCertDir", "data/temp/parentcerts/", "PathToParentCertDir")

}

func main() {
	rootCmd.AddCommand(WipeDB)
	rootCmd.AddCommand(AddTestDT)
	rootCmd.AddCommand(AddDTBatch)
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}

}
