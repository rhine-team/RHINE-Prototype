package main

import (
	"context"
	//"encoding/hex"
	"log"
	"net"

	//cx509 "crypto/x509"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth/cbor"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/components/ca"
	ps "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/parentserver"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/components/parentserver/pserver"

	//"github.com/grantae/certinfo"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
	"github.com/spf13/cobra"

	//"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var ParentConfig string

var ChildConfig string
var ZoneName string
var ParentServer string
var OutputPath string
var ZoneIsIndependent bool
var ZoneIsDelegationOnly bool

var rootCmd = &cobra.Command{
	Use:   "run_zoneManager",
	Short: "ZoneManager for RHINE",
	Long:  "ZoneManager for RHINE, can act as parent or child.",
}

var RequestDelegCmd = &cobra.Command{
	Example: "./run_zoneManager RequestDeleg",
	Use:     "RequestDeleg",
	Short:   "Use to request a delegation",
	Long:    "Use to request a delegation to receive a RCertificate",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Input
		expirationTime := time.Now().Add(time.Hour * 24 * 180)
		revocationBit := 0

		// Parse config
		cof, errparse := rhine.LoadZoneConfig(ChildConfig)
		if errparse != nil {
			log.Fatalf("Could not parse the config file.")
		}

		// Overwrite config if needed
		if ZoneName != "" {
			cof.ZoneName = ZoneName
		}

		if ParentServer != "" {
			cof.ParentServerAddr = ParentServer
		}

		// Construct AuthorityLevel
		authl := 0b0000
		if ZoneIsIndependent {
			authl += 0b0001
		}
		if ZoneIsDelegationOnly {
			authl += 0b1000
		}
		var reqAuthorityLevel rhine.AuthorityLevel
		reqAuthorityLevel = rhine.AuthorityLevel(authl)

		// Make a new ZoneManager
		nzm := rhine.NewZoneManager(cof)

		// Make a new Csr
		csr, errcsr := nzm.CreateSignedCSR(reqAuthorityLevel, expirationTime, nzm.Ca, nzm.LogList, revocationBit)
		if errcsr != nil {
			log.Fatalf("Creation of the csr failed! ", errcsr)
			return
		}
		log.Println("Created a signed CSR")

		// Connect to the parent
		conn := rhine.GetGRPCConn(cof.ParentServerAddr)
		log.Println("Established connection to Parent at: ", cof.ParentServerAddr)

		defer conn.Close()
		c := ps.NewParentServiceClient(conn)

		// Send delegation request to the server
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		r, err := c.InitDelegation(ctx, &ps.InitDelegationRequest{Rid: csr.ReturnRid(), Csr: csr.ReturnRawBytes()})
		if err != nil {
			log.Fatalf("No response from ParentServer: %v", err)
		}
		//log.Println("Received a response from parent for Delegation Req.: ", r)
		log.Println("Received a response from parent for Delegation Request")
		// Close connection
		conn.Close()

		// Parse the response
		apv := &rhine.RhineSig{
			Data:      r.Approvalcommit.Data,
			Signature: r.Approvalcommit.Sig,
		}

		// Parse parent certificate
		pcertp, certerr := x509.ParseCertificate(r.Rcertp)
		if certerr != nil {
			log.Fatalf("Certificate Parsing failure: %v", certerr)
		}

		// Check wheter acsr is valid
		if !apv.Verify(pcertp.PublicKey) {
			log.Fatal("Checking acsr failed")
		}

		// Forward response content to CA
		caacsr := &ca.RhineSig{
			Data: r.Approvalcommit.Data,
			Sig:  r.Approvalcommit.Sig,
		}

		connCA := rhine.GetGRPCConn(cof.CAServerAddr)

		defer connCA.Close()
		cca := ca.NewCAServiceClient(connCA)

		// Send delegation request to the  CA server
		ctxca, cancelca := context.WithTimeout(context.Background(), time.Second)
		defer cancelca()

		rCA, errca := cca.SubmitNewDelegCA(ctxca, &ca.SubmitNewDelegCARequest{Rcertp: r.Rcertp, Acsr: caacsr, Rid: csr.ReturnRid()})
		if errca != nil {
			log.Println("Request Delegation failed!")
			log.Fatalf("No reponse from CA: %v", err)
		}

		//TODO More Checks
		childce, parseerr := x509.ParseCertificate(rCA.Rcertc)
		if parseerr != nil {
			log.Fatal("Failed parsing returned RHINE cert ", parseerr)
		}

		if rhine.StoreCertificatePEM(OutputPath, rCA.Rcertc) != nil {
			log.Fatal("Failed storing returned RHINE cert")
		}
		log.Printf("Certificate: %+v ", childce)
		log.Println("Certificate stored")

		// Print the cert

		/*
			newchildcert, _ := cx509.ParseCertificate(rCA.Rcertc)
			prettyCert, _ := certinfo.CertificateText(newchildcert)
			log.Println("\n", prettyCert)
		*/

	},
}

var RunParentServer = &cobra.Command{
	Example: "./run_zoneManager RunParentServer",
	Use:     "RunParentServer",
	Short:   "Runs the ParentServer",
	Long:    "Runs the ParentServer, needed by children during inital delegation",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadZoneConfig(ParentConfig)
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
		ps.RegisterParentServiceServer(s, &pserver.PServer{Zm: nzm})

		log.Println("ParentServer is running.")
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

func init() {
	RequestDelegCmd.Flags().StringVar(&ZoneName, "zone", "", "NameOfChildZone")
	RequestDelegCmd.Flags().StringVar(&OutputPath, "output", "data/childCertRHINE.pem", "Address with port of parent server")
	RequestDelegCmd.Flags().StringVar(&ChildConfig, "config", "configs/childExample.json", "ConfigPath")
	RequestDelegCmd.Flags().BoolVar(&ZoneIsIndependent, "ind", true, "Flag Independent ChildZone")
	RequestDelegCmd.Flags().BoolVar(&ZoneIsDelegationOnly, "delegOnly", false, "Flag Independent ChildZone")
	RequestDelegCmd.Flags().StringVar(&ParentServer, "parentaddr", "", "Address with port of parent server")

	RunParentServer.Flags().StringVar(&ParentConfig, "config", "configs/parentExample.json", "ConfigPath")
}

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
