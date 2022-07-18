package main

import (
	//"context"
	"log"
	"net"

	//"github.com/rhine-team/RHINE-Prototype/offlineAuth2/cbor"
	//pf "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/log"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/aggregator"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/aggregator/aggserver"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"
	"github.com/spf13/cobra"

	//"github.com/spf13/viper"
	"google.golang.org/grpc"
	//"google.golang.org/grpc/credentials/insecure"
)

var configPath = "configs/configAgg.json"

var rootCmd = &cobra.Command{
	Use:   "run_Aggregator",
	Short: "TODO",
	Long:  "TODO",
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadAggConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the aggregator config file.")
		}

		// Make a new Log struct
		aggr := rhine.NewAggManager(cof)

		// Run the Log
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

func main() {
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}

}
