package main

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/rhine-team/RHINE-Prototype/common"
	"github.com/rhine-team/RHINE-Prototype/rhinesigner"
	"log"
	"os"
)

func main() {

	args := os.Args

	if len(args) != 4 {
		log.Fatal("Invalid number of arguments")
	}

	rzone, err := loadAndParseZF(args[1])
	if err != nil {
		log.Fatal("Could not load zonefile ", err, args[1])
	}

	cert, err := common.LoadCertificatePEM(args[2])
	if err != nil {
		log.Fatal("Could not load certificate ", err, args[2])
	}
	key, err := common.LoadPrivateKeyEd25519(args[3])
	if err != nil {
		log.Fatal("Could not load key ", err, args[3])
	}

	rzone.Origin = rzone.Rrs[dns.Type(dns.TypeSOA)][0].Header().Name
	rzone.Print()
	fmt.Println("Signing\n")
	rzone.Sign(cert, key, rzone.Origin)
	rzone.Print()

}

func loadAndParseZF(path string) (*rhinesigner.Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	zone := rhinesigner.Zone{
		Origin: "",
		Rrs:    make(map[dns.Type][]dns.RR),
	}

	zp := dns.NewZoneParser(f, "rhine-ns.com", path)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		zone.Rrs[dns.Type(rr.Header().Rrtype)] = append(zone.Rrs[dns.Type(rr.Header().Rrtype)], rr)
	}

	return &zone, nil
}