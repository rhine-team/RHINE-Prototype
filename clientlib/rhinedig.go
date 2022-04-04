package main

import (
	"clientlib/rhine"
	"fmt"
	flag "github.com/spf13/pflag"
	"strconv"
	"strings"
)

var rhineVerification = flag.BoolP("rhineVerify", "r", false,
	"use rhine-style verification of signed assertions (using RCert)")
var dnssecVerification = flag.BoolP("dnssecVerify", "s", false,
	"use dnssec-style verification of signed records (authentication chain)")
var port = flag.UintP("port", "p", 53, "port for dns resolver")

func main() {
	flag.Parse()
	var name, server string
	args := flag.Args()
	var nameset, serverset bool

	for _, a := range args {
		if strings.HasPrefix(a, "@") {
			server = a[1:]
			serverset = true
		} else {
			name = a
			nameset = true
		}

	}

	if !nameset || !serverset {
		fmt.Println("Not enough arguments: use ./rhinedig @server name\nExample: ./rhinedig @8.8.8.8 www.google.ch\nFlags:")
		flag.Usage()
		return
	}

	if ok := strings.HasSuffix(name, "."); !ok {
		name += "."
	}

	var res string

	portstr := strconv.Itoa(int(*port))

	if flag.Lookup("rhineVerify").Changed {
		res = rhine.QueryNameRhine(name, server, portstr)
	} else if flag.Lookup("dnssecVerify").Changed {
		res = rhine.QueryNameDNSSEC(name, server, portstr)
	} else {
		res = rhine.QueryNameDNS(name, server, portstr)
	}

	fmt.Println(res)

}
