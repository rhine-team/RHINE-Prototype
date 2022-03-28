package main

import (
	"fmt"
	logger15 "github.com/inconshreveable/log15"
	"github.com/rhine-team/RHINE-Prototype/ca"
	"log"
	"os"
)

func main() {
	var logger = logger15.New("Module", "CA")

	var configPath string
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	} else {
		configPath = "config/caconfig.conf"
	}
	config, err := ca.LoadConfig(configPath)
	if err != nil {
		log.Fatal("Error loading config: ", err)
	}
	myca := ca.NewCA(config)

	logger.Info(fmt.Sprintf("CA Created: %#v\n", myca))

	myca.RunServer(myca.Address)

}
