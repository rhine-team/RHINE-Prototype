package main

import (
	"fmt"
	logger15 "github.com/inconshreveable/log15"
	"github.com/rhine-team/RHINE-Prototype/checkerExtension"
	"log"
	"os"
)

func main() {
	var logger = logger15.New("Module", "CheckerExtension")

	var configPath string
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	} else {
		configPath = "config/checkerconfig.conf"
	}
	config, err := checkerExtension.LoadConfig(configPath)
	if err != nil {
		log.Fatal("Error loading config: ", err)
	}

	checker := checkerExtension.NewChecker(config)
	logger.Info(fmt.Sprintf("Checker Created: %#v\n", checker))

	checker.RunServer(checker.Address)
}
