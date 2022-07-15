package main

import (
	"context"
	//"encoding/hex"
	"log"

	"time"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/cbor"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/ca"
	ps "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/parentserver"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/parentserver/server/pserver"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"
	"github.com/spf13/cobra"

	//"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var rootCmd = &cobra.Command{
	Use:   "run_zoneManager",
	Short: "TODO",
	Long:  "TODO",
}

var RequestDelegCmd = &cobra.Command{
	Example: "./run_zoneManager RequestDeleg",
	Use:     "RequestDeleg",
	Short:   "TODO",
	Long:    "TODO",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Input
		newZoneName := "example.ethz.ch"
		parentServer := "localhost:10004"
		reqAuthorityLevel := 0b0001
		expirationTime := time.Now().Add(time.Hour * 24 * 180)

		// Parse config
		configPath := "configs/childExample.json"
		cof, errparse := rhine.LoadZoneConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the config file.")
			return
		}

		cof.ZoneName = newZoneName
		cof.ParentServerAddr = parentServer

		// Make a new ZoneManager
		nzm := rhine.NewZoneManager(cof)

		// Make a new Csr
		csr, errcsr := CreateSignedCSR(reqAuthorityLevel, expirationTime, []rhine.Authority{}, []rhine.Log{}, 0)
		if errcsr != nil {
			log.Fatalif("Creation of the csr failed!")
			return
		}

		// Connect to the parent
		conn := getGRPCConn(cof.ParentServerAddr)

		defer conn.Close()
		c := ps.NewParentServiceClient(conn)

		// Send delegation request to the server
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r, err := c.InitDelegation(ctx, &ps.InitDelegationRequest{Rid: csr.ReturnRid(), Csr: csr.ReturnRawBytes()})
		if err != nil {
			log.Fatalf("could not get a response: %v", err)
		}

		// Parse the response
		apv := &rhine.RhineSig{
			Data:          r.Approvalcommit.Data,
			Signature:     r.Approvalcommit.Sig,
			Supportedalgo: 0,
		}

		// Parse parent certificate
		pcertp, certerr := x509.ParseCertificate(r.Rcertp)
		if certerr != nil {
			log.Fatalf("Certificate Parsing failure: %v", certerr)
		}

		// Check wheter acsr is valid
		if !apv.Verify(pcertp.PublicKey) {
			log.Fatalln("Checking acsr failed")
		}

		// Forward response content to CA
		caacsr := &ca.RhineSig{
			Data:          r.Approvalcommit.Data,
			Sig:           r.Approvalcommit.Sig,
			Supportedalgo: 0, // TODO  change that!
		}

		conn := getGRPCConn(cof.CAServerAddr)

		defer conn.Close()
		cca := ca.NewCAServiceClient(conn)

		// Send delegation request to the server
		ctxca, cancelca := context.WithTimeout(context.Background(), time.Second)
		defer cancelca()

		rca, errca := cca.SubmitNewDelegCA(ctxca, &ca.SubmitNewDelegCARequest{Rcertp: r.Rcertp, Acsr: caacsr})
		if errca != nil {
			log.Fatalf("could not get a response: %v", err)
		}

		log.Println("Test run succesfull")
	},
}

var RunParentServer = &cobra.Command{
	Example: "./run_zoneManager RunParentServer",
	Use:     "RequestDeleg",
	Short:   "TODO",
	Long:    "TODO",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		configPath := "configs/parentExample.json"
		cof, errparse := rhine.LoadZoneConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the config file.")
		}

		// Make a new ZoneManager
		nzm := rhine.NewZoneManager(cof)

		lis, err := net.Listen("tcp", cof.ServerAddress)
		if err != nil {
			log.Fatalf("Listen failed: %v", err)
		}

		s := grpc.NewServer()
		pf.RegisterCAServiceServer(s, &pserver.PServer{Zm: nzm})

		if err := s.Serve(lis); err != nil {
			log.Fatalf("Serving failed: %v", err)
		}

	},
}

/*
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error while executing CLI '%s'", err)
		os.Exit(1)
	}
}
*/

func main() {
	rootCmd.AddCommand(RequestDelegCmd)
	rootCmd.AddCommand(RunParentServer)
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}

	// Read config files
	/*
		viper.SetConfigName("parent")
		viper.SetConfigType("json")
		viper.AddConfigPath("config/")

		if err := viper.ReadInConfig(); err != nil {
			log.Fatalf("Fatal error config file: %v \n", err)
		}
	*/
}
