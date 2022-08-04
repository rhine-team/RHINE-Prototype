package main

import (
	"log"
	"net"

	pf "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/log"
	ls "github.com/rhine-team/RHINE-Prototype/offlineAuth/components/log/logserver"

	"github.com/rhine-team/RHINE-Prototype/offlineAuth/rhine"
	"github.com/spf13/cobra"

	"google.golang.org/grpc"
)

var configPath string

var rootCmd = &cobra.Command{
	Use:   "run_Log",
	Short: "Front-end logger",
	Long:  "Front-end logger for RHINE, connects to a trillian-based CT backend",
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadLogConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the config file.")
		}

		// Make a new Log struct
		logm := rhine.NewLogManager(cof)

		// Retrieve DSA from aggregator!
		logm.GetDSAfromAggregators()

		// Run the Log
		lis, err := net.Listen("tcp", cof.ServerAddress)
		if err != nil {
			log.Fatalf("Listen failed: %v", err)
		}

		s := grpc.NewServer()
		pf.RegisterLogServiceServer(s, &ls.LogServer{LogManager: logm})

		log.Println("Rhine Log server online at: ", cof.ServerAddress)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Serving failed: %v", err)
		}
	},
}

var WipeDB = &cobra.Command{
	Example: "./run_Aggregator WipeDB",
	Use:     "WipeDB",
	Short:   "Wiped the Logger Delegation Transperancy DB",
	Long:    "Deletes everything from the badger DB of the Logger",
	Args:    nil,
	Run: func(cmd *cobra.Command, args []string) {
		// Parse config
		cof, errparse := rhine.LoadLogConfig(configPath)
		if errparse != nil {
			log.Fatalf("Could not parse the config file.")
		}

		// Make a new Log struct
		logm := rhine.NewLogManager(cof)

		log.Println("New Logger Manager initialized")

		err := logm.DB.DropAll()
		if err != nil {
			log.Println("Deletions failed!")
		} else {
			log.Println("All badger data has been dropped with succes!")
		}
	},
}

func init() {
	rootCmd.Flags().StringVar(&configPath, "config", "configs/configLog.json", "ConfigPath")
	WipeDB.Flags().StringVar(&configPath, "config", "configs/configLog.json", "ConfigPath")
}

func main() {
	rootCmd.AddCommand(WipeDB)
	err := rootCmd.Execute()
	if err != nil {
		log.Fatal(err)
	}

}
