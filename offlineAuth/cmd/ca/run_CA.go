package main

import (
	//"context"
	"log"
	"net"

	_ "github.com/rhine-team/RHINE-Prototype/offlineAuth/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/ca"
	cs "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/ca/caserver"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
	"github.com/spf13/cobra"

	//"github.com/spf13/viper"
	"google.golang.org/grpc"
	//"google.golang.org/grpc/credentials/insecure"
)

var configPath string

var rootCmd = &cobra.Command{
	Use:   "run_CA",
	Short: "CA Server",
	Long:  "Runs the Certificate Authority for RHINE",
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadCAConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the config file.")
		}

		// Make a new CA struct
		cas := rhine.NewCA(cof)

		// Run the CA
		lis, err := net.Listen("tcp", cof.ServerAddress)
		if err != nil {
			log.Fatalf("Listen failed: %v", err)
		}

		s := grpc.NewServer()
		pf.RegisterCAServiceServer(s, &cs.CAServer{Ca: cas})

		log.Println("RHINE Certificate Authority is online at: ", cof.ServerAddress)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Serving failed: %v", err)
		}
	},
}

func init() {
	rootCmd.Flags().StringVar(&configPath, "config", "configs/configCA.json", "ConfigPath")
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}

}
