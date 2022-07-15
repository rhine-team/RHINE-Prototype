package main

import (
	//"context"
	"log"
	"net"

	//"github.com/rhine-team/RHINE-Prototype/offlineAuth2/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/ca"
	cs "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/ca/caserver"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"
	"github.com/spf13/cobra"

	//"github.com/spf13/viper"
	"google.golang.org/grpc"
	//"google.golang.org/grpc/credentials/insecure"
)

var configPath = "configs/configCA.json"

var rootCmd = &cobra.Command{
	Use:   "run_CA",
	Short: "TODO",
	Long:  "TODO",
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

		if err := s.Serve(lis); err != nil {
			log.Fatalf("Serving failed: %v", err)
		}
	},
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}

}
