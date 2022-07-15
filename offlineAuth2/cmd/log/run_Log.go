package main

import (
	//"context"
	"log"
	"net"

	//"github.com/rhine-team/RHINE-Prototype/offlineAuth2/cbor"
	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/log"
	ls "github.com/rhine-team/RHINE-Prototype/offlineAuth2/components/log/logserver"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth2/rhine"
	"github.com/spf13/cobra"

	//"github.com/spf13/viper"
	"google.golang.org/grpc"
	//"google.golang.org/grpc/credentials/insecure"
)

var configPath = "configs/configLog.json"

var rootCmd = &cobra.Command{
	Use:   "run_Log",
	Short: "TODO",
	Long:  "TODO",
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadLogConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the config file.")
		}

		// Make a new Log struct
		logm := rhine.NewLogManager(cof)

		// Run the Log
		lis, err := net.Listen("tcp", cof.ServerAddress)
		if err != nil {
			log.Fatalf("Listen failed: %v", err)
		}

		s := grpc.NewServer()
		pf.RegisterCAServiceServer(s, &ls.LogServer{LogManager: logm})

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
