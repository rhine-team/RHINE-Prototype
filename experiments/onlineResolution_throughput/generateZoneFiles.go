package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"
	"strconv"

	"io/ioutil"
	"log"

	"github.com/miekg/dns"

)

func init() {
	rand.Seed(time.Now().UnixNano())
}




//var dim = []int{20, 100, 3, 2}
//var dim = []int{15, 80, 10, 10}
var dim = []int{15, 8000, 1, 1}
//var dim = []int{15, 10, 5, 3}
var deployPort = ":53"
//var dim = []int{15, 4, 1, 2}
var glue = []string{"10.114.16.4", "10.114.16.5", "10.114.16.6", "10.114.16.7"}
var glue6 = []string{"fe80::70d9:8ff:fe10:32c7", "fe80::78df:f4ff:fe74:91d6", "fe80::ccaa:7cff:feb3:b893", "fe80::a837:26ff:fe7c:4fce"}
var parentnames = []string{""}
var dnsseckeyfolder = "./testdata/dnsseckeys"
var rootki = ""

var counter = 0

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz1234567890")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	//suffix := []string{}
	var allRecords []string

	fmt.Println("Starting")

/*
	// create config for level
	confRHINE, _ := os.Create("./configs/" + "rhine/" +"Corefile_level" + strconv.Itoa(i))
	confSEC, _ := os.Create("./configs/" + "dnssec/" +"Corefile_level" + strconv.Itoa(i))

	// create signing config for level
	confSignRHINE, _ := os.Create("./configsSigning/" + "rhine/" + "CorefileS_level" + strconv.Itoa(i))
	confSignSEC, _ := os.Create("./configsSigning/" +  "dnssec/" +"CorefileS_level" + strconv.Itoa(i))
*/

	os.MkdirAll("./configs/rhine", os.ModePerm)
	os.MkdirAll("./configs/dnssec", os.ModePerm)
	os.MkdirAll("./configsSigning/rhine", os.ModePerm)
	os.MkdirAll("./configsSigning/dnssec", os.ModePerm)

	os.MkdirAll("./testdata/zonefiles/level0", os.ModePerm)
	os.MkdirAll("./testdata/zonefiles/level1", os.ModePerm)
	os.MkdirAll("./testdata/zonefiles/level2", os.ModePerm)
	os.MkdirAll("./testdata/zonefiles/level3", os.ModePerm)

	os.MkdirAll("./testdata/zonefilesDNSSEC/level0", os.ModePerm)
	os.MkdirAll("./testdata/zonefilesDNSSEC/level1", os.ModePerm)
	os.MkdirAll("./testdata/zonefilesDNSSEC/level2", os.ModePerm)
	os.MkdirAll("./testdata/zonefilesDNSSEC/level3", os.ModePerm)


	os.MkdirAll("./testdata/dnssecRES/level0", os.ModePerm)
	os.MkdirAll("./testdata/dnssecRES/level1", os.ModePerm)
	os.MkdirAll("./testdata/dnssecRES/level2", os.ModePerm)
	os.MkdirAll("./testdata/dnssecRES/level3", os.ModePerm)

	os.MkdirAll("./testdata/rhineRES/level0", os.ModePerm)
	os.MkdirAll("./testdata/rhineRES/level1", os.ModePerm)
	os.MkdirAll("./testdata/rhineRES/level2", os.ModePerm)
	os.MkdirAll("./testdata/rhineRES/level3", os.ModePerm)

	os.MkdirAll("./testdata/dnsseckeys", os.ModePerm)

  // Parse key (we reuse)

	// create signing config for level
	confSignRHINE, _ := os.Create("./configsSigning/" + "rhine/" + "CorefileS")
	confSignSEC, erril := os.Create("./configsSigning/" +  "dnssec/" +"CorefileSS")

	fmt.Println(erril)

	// Create root key
	genKeyRecord([]string{"."})

	for i := 0; i < 4; i++ {
		// create config for level
		confRHINE, _ := os.Create("./configs/" + "rhine/" +"Corefile_" + "level" + strconv.Itoa(i))
		confSEC, _ := os.Create("./configs/" + "dnssec/" +"Corefile_" + "level" + strconv.Itoa(i))
		confVAN, _ := os.Create("./configs/" + "dnssec/" +"CorefileVan_" + "level" + strconv.Itoa(i))


		// temporary new zones store
		newzones := []string{}
		dnssec_sign := ""
		rhine_sign := ""

		dnssec_conf_part:= ""
		rhine_conf_part := ""
		root := "./testdata"

		// End zones
		if (false) {

		} else {
			// Deleg only
			// Generate all zones for this

			subnames := []string{}
			for  _ , parentzone := range parentnames {
				// Create new subnames
				mysubnames := []string{}
				for u := 0; u < dim[i]; u++ {
					nName := RandStringRunes(6)
					nName = nName + "." + parentzone
					//allRecords = append(allRecords, nName)
					newzones = append(newzones, nName)
					subnames = append(subnames, nName)
					mysubnames = append(mysubnames, nName)
				}

				// Generate keys for all mysubnames
				dslist := genKeyRecord(mysubnames)

				randName := parentzone
				if parentzone == "" {
				  randName = "."
				}

				if counter % 100 == 0{
					fmt.Println("Writing: ", randName)
					fmt.Println("Number: ", fmt.Sprintf("%d", counter))
				}
				// write the zone zonefile and add needed stuff
				// RHINE
			  fileloc := 	"testdata/zonefiles/" + "level" + strconv.Itoa(i)
				filelocfinal := fileloc + "/" + "db." + randName
				//filelocfinalSHORT := "zonefiles/"  + "/" + "db." + randName
				zonefile, _ := os.Create( "./" + filelocfinal )

				//filelocfinalRES := "rhineRES/" + "level" + strconv.Itoa(i)

				SOA := "%s	604800	IN	SOA	ns.%s hostmaster.%s 1659288904 604800 86400 2419200 604800\n%s	604800	IN	NS	ns.%s\n"
				SOA = fmt.Sprintf(SOA, randName, randName, randName, randName, randName)
				if (i == 0) {
					SOA = ".	604800	IN	SOA	sri-nic.arpa. hostmaster.sri-nic.arpa. 1659288904 604800 86400 2419200 604800\n.	604800	IN	NS	sri-nic.arpa.\n"
				}

				// NS
				nschain := ""
				allDS := ""
				if(i != 3) {
					for ind, mysu := range mysubnames {
						NS := "%s	604800	IN	NS	ns.%s\n%s	604800	IN	A	%s\n"
						NS = fmt.Sprintf(NS, mysu, mysu, "ns." + mysu, glue[i+1])


						NSA := "%s	604800	IN	AAAA	%s\n"
						NSA = fmt.Sprintf(NSA, "ns." + mysu, glue6[i+1])
						nschain = nschain + NS + NSA

						// ADD DS RECORDS
						allDS = allDS + dslist[ind]
					}
				}

				zonefile.WriteString(SOA)
				zonefile.WriteString(nschain)



				// SEC
				filelocSEC := 	"testdata/zonefilesDNSSEC/" + "level" + strconv.Itoa(i)
				filelocfinalSEC := filelocSEC + "/" + "db." + randName
				zonefileSEC, _ := os.Create("./" + filelocfinalSEC)
				zonefileSEC.WriteString(SOA)
				zonefileSEC.WriteString(nschain)

				zonefileSEC.WriteString(allDS)

				//ENd records
				if (i== 3) {
					for _, uj := range mysubnames{
						allRecords = append(allRecords, uj )

						zonefileSEC.WriteString(fmt.Sprintf("%s 604800	IN	A	198.0.0.1\n", uj))
						zonefileSEC.WriteString(fmt.Sprintf("%s 604800	    IN	AAAA	2400:cb00:2049:1::a29f:1804\n", uj))

						zonefile.WriteString(fmt.Sprintf("%s 604800	IN	A	198.0.0.1\n", uj))
						zonefile.WriteString(fmt.Sprintf("%s 604800	    IN	AAAA	2400:cb00:2049:1::a29f:1804\n", uj))

						//zonefile.WriteString(fmt.Sprintf("%s 604800	IN	A	198.0.0.1\n", uj))
						//zonefile.WriteString(fmt.Sprintf("%s 604800	IN	IN	AAAA	2400:cb00:2049:1::a29f:1804\n", uj))
					}
				}

				dnssecRES := "dnssecRES" + "/level" + strconv.Itoa(i)

				//keyfile := root + "/zsk/key.key"

				signsec := `sign %s {
						key file %s
						directory %s
				}
				`

				rhinesec := `sign %s {
						key file %s
						directory %s
						rcert file %s
				}
				`
				//						logger file %s

				certloc := "testdata/key"
				//loggerloc := "log.private"
				rhineRES := "rhineRES" + "/level" + strconv.Itoa(i)

				dnssec_sign =  fmt.Sprintf(signsec, "zonefilesDNSSEC/" + "level" + strconv.Itoa(i) + "/" + "db." + randName , "dnsseckeys" + "/D" +randName + "D", dnssecRES)
				rhine_sign =  fmt.Sprintf(rhinesec, "zonefiles/"+ "level" + strconv.Itoa(i) + "/" + "db." + randName , "dnsseckeys" + "/D" +randName + "D", rhineRES, certloc)


				dnssecsign := `
					%s:10009 {
							root %s
							%s
					}

				`

				rhinesig := `
					%s:10009 {
							root %s
							%s
					}

				`

				dnssecsign = fmt.Sprintf(dnssecsign, randName, root, dnssec_sign)


				confSignSEC.WriteString(dnssecsign)
				//fmt.Println(dnssecsign)


				rhinesign := fmt.Sprintf(rhinesig, randName, root, rhine_sign)
				confSignRHINE.WriteString( rhinesign)





				rhine_no := `rhine %s %s {
						scion off
				}
				`
				rhine_no = fmt.Sprintf(rhine_no,  "rhineRES/" + "level" + strconv.Itoa(i) + "/" + "db." + randName + "signed", randName)
				rhine_conf_part = rhine_no



			  dnssec_no := "file %s %s \n"
				dnssec_no = fmt.Sprintf(dnssec_no,  "dnssecRES/" + "level" + strconv.Itoa(i) + "/" + "db." + randName + "signed", randName)
				dnssec_conf_part = 	 dnssec_no

				// ADD NEW SERVER BLOCK
				secconf := `%s%s  {
							root %s
							%s
					}

				`

				rconf := `%s%s  {
							root %s
							%s
					}

				`

				vaniconf := `%s%s  {
							root %s
							%s
					}

				`

				vanconf_no := "file %s %s \n"

				secconf = fmt.Sprintf(secconf, randName, deployPort, root, dnssec_conf_part)

				rhine_conf_part = fmt.Sprintf(rconf, randName, deployPort, root, rhine_conf_part)

				vanconfpart := fmt.Sprintf(vanconf_no,  "zonefiles/" + "level" + strconv.Itoa(i) + "/" + "db." + randName , randName)
				vanconf := fmt.Sprintf(vaniconf, randName, deployPort, root, vanconfpart)

				confSEC.WriteString(secconf)
				confVAN.WriteString(vanconf)
				confRHINE.WriteString(rhine_conf_part)

				zonefileSEC.Sync()
				zonefileSEC.Close()



				zonefile.Sync()
				zonefile.Close()

				//TODO
				counter++


			}
			// ADD children

			// add configs


			parentnames = subnames

		}

		confRHINE.Sync()
		confRHINE.Close()

		confSEC.Sync()
		confSEC.Close()

		confVAN.Sync()
		confVAN.Close()

	}

	confSignSEC.Sync()
	confSignSEC.Close()

	confSignRHINE.Sync()
	confSignRHINE.Close()


	// ALL FILES
	alrec, _ := os.Create("allrecords")
	once, _ := os.Create("once")
	for _, a := range allRecords {
		for z := 0; z < 4; z++ {
			alrec.WriteString(fmt.Sprintf("%s A\n", a))
		}
			once.WriteString(fmt.Sprintf("%s A\n", a))
	}
	alrec.Sync()
	alrec.Close()

	fmt.Println(rootki)
}


func genKeyRecord(zones []string) []string {
	resi := []string{}
	for _, zone := range zones {
		key := &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Class: dns.ClassINET, Ttl: 36000, Rrtype: dns.TypeDNSKEY},
			Algorithm: dns.ECDSAP256SHA256, Flags: 257, Protocol: 3,
		}
		priv, err := key.Generate(256)
		if err != nil {
			log.Fatal(err)
		}

		ds := key.ToDS(dns.SHA256)
		if zone == "." {
			rootki = "Root Key: " + key.String()+"\n"
		}

		//base := fmt.Sprintf(dnsseckeyfolder + "/" + zone + ".private", key.Header().Name, key.Algorithm, key.KeyTag())
		base := dnsseckeyfolder + "/D" + zone + "D"
		if err := ioutil.WriteFile(base+".key", []byte(key.String()+"\n"), 0644); err != nil {
			log.Fatal(err)
		}
		if err := ioutil.WriteFile(base+".private", []byte(key.PrivateKeyString(priv)), 0600); err != nil {
			log.Fatal(err)
		}

		resi = append(resi, ds.String() + "\n")
	}

	return resi
}
