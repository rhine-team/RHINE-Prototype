package main

import (
	//"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"path/filepath"
	"strconv"
	"strings"

	//"time"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/rhine-team/RHINE-Prototype/pkg/rhine"

	//"golang.org/x/exp/slices"
	//"github.com/google/certificate-transparency-go/x509"
	//"github.com/google/certificate-transparency-go/x509util"
	_ "github.com/rhine-team/RHINE-Prototype/internal/cbor"
	"github.com/rhine-team/RHINE-Prototype/internal/components/ca"
	ps "github.com/rhine-team/RHINE-Prototype/internal/components/parentserver"

	//"github.com/rhine-team/RHINE-Prototype/internal/components/parentserver/pserver"
	//"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

// This script should be run on the parent server

var zoneFixed = ".benchmark.ch"
var childkeyPrefix = "CHILDPK_"
var parentKeyPrefix = "PARENTSK_"
var parentCertPrefix = "PARENTCERT_"
var counterDone uint64
var counterSend uint64
var counterGo uint64

func main() {
	fmt.Println("The following arguments needed: [ChildConfigPath (1)] [ChildKeyFileDir 2] [RequestRate 3] [Consoleoff 4]")
	// Path must end in a slash

	if len(os.Args) < 5 {
		log.Fatal("Need 3 arguments, not ", os.Args)
	}

	sleeptime, _ := strconv.Atoi(os.Args[3])

	noout := false
	if os.Args[4] == "nostd" {
		noout = true
	}

	if false {
		// Open  parent database (should be created if not existing yet)
		db, errdb := badger.Open(badger.DefaultOptions(os.Args[1]))
		if errdb != nil {
			log.Fatal("Badger error: ", errdb)
		}
		defer db.Close()

		child := []string{}
		err := db.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchSize = 10
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				item := it.Item()
				k := item.Key()
				err := item.Value(func(v []byte) error {
					//fmt.Printf("key=%s, value=%s\n", k, v)
					ki := string(k)
					if strings.HasPrefix(ki, childkeyPrefix) {
						child = append(child, strings.TrimPrefix(ki, childkeyPrefix))
					}
					return nil
				})
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Fatalln("Error db: ", err)
		}
	}
	//log.Println("childs", child)
	log.Println("Db read")

	childKeyPath := []string{}
	childNames := []string{}

	filepath.Walk(os.Args[2], func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatalf(err.Error())
		}
		//fmt.Printf("File Name: %s\n", info.Name())
		if !strings.Contains(info.Name(), "_pub") && strings.Contains(info.Name(), ".pem") {
			zoneName := strings.Replace(info.Name(), ".pem", "", 1)
			childNames = append(childNames, zoneName)
			childKeyPath = append(childKeyPath, os.Args[2]+"/"+info.Name())
		}
		return nil
	})

	// Init connections
	// Connect to the parent
	// Parse config
	var errparse error
	cof, errparse := rhine.LoadZoneConfig(os.Args[1])
	if errparse != nil {
		return
		//log.Fatalf("Could not parse the config file.")
	}

	connCA := rhine.GetGRPCConn(cof.CAServerAddr)

	defer connCA.Close()

	conni := rhine.GetGRPCConn(cof.ParentServerAddr)
	log.Println("Established connection to Parent at: ", cof.ParentServerAddr)
	defer conni.Close()

	count := 0
	//startTime := time.Now()
	intervalTime := time.Now()

	go func() {
		if true {
			for true {
				elapsed := time.Since(intervalTime)
				intervalTime = time.Now()
				fmt.Println("Go routine start rate: ", float64(count)/elapsed.Seconds())

				count = 0
				ui := atomic.LoadUint64(&counterSend)
				uil := atomic.LoadUint64(&counterDone)
				started := atomic.LoadUint64(&counterGo)
				fmt.Println("Sending to CA rate: ", float64(ui)/elapsed.Seconds())
				fmt.Println("Finished deleg  rate: ", float64(uil)/elapsed.Seconds())
				fmt.Println("STARTED GO ROUTINES: ", float64(started)/elapsed.Seconds())
				atomic.StoreUint64(&counterDone, 0)
				atomic.StoreUint64(&counterSend, 0)
				atomic.StoreUint64(&counterGo, 0)
				time.Sleep(5 * time.Second)
			}
		}
	}()

	for i, name := range childNames {
		go runChild(os.Args[1], name, childKeyPath[i], noout, conni, connCA, cof)
		if !noout {
			log.Println("Started go routine, ", i)
		}
		time.Sleep(time.Duration(sleeptime) * time.Microsecond)
		if !noout {
			log.Println("Sleep")
		}

	}
	for true {
	}

	//log.Println("childnames", childNames)
	//log.Println("keypath", childKeyPath)

	/*
		for i, name := range childNames {
			cmdI := fmt.Sprint("../build/zoneManager RequestDeleg --config ", os.Args[1], " --output data/certs/delegResultCert.pem ", "--zone ", name, " --privkey ", childKeyPath[i], " &")
			cmd := exec.Command("bash", "-c", cmdI)
			//stderr, _ := cmd.StderrPipe()
			if err := cmd.Start(); err != nil {
				log.Println(err)
			}
			log.Println("Started a client run")
			log.Println(cmdI)

			time.Sleep(time.Duration(sleeptime) * time.Microsecond)

		}
	*/

}

func runChild(confPath string, ZoneName string, PrivateKeyPath string, consoleOff bool, connec *grpc.ClientConn, conna *grpc.ClientConn, cof rhine.ZoneConfig) {
	if consoleOff {
		rhine.DisableConsoleOutput()
	}

	atomic.AddUint64(&counterGo, 1)

	var timeout = time.Second * 1000

	/*
		// Parse config
		var errparse error
		cof, errparse := rhine.LoadZoneConfig(confPath)
		if errparse != nil {
			return
			//log.Fatalf("Could not parse the config file.")
		}
	*/

	// Overwrite config if needed
	if ZoneName != "" {
		cof.ZoneName = ZoneName
	}

	if PrivateKeyPath != "" {
		cof.PrivateKeyPath = PrivateKeyPath
	}

	// Input
	expirationTime := time.Now().Add(time.Hour * 24 * 180)
	revocationBit := 0

	// Construct AuthorityLevel
	authl := 0b0000
	if true {
		authl += 0b0001
	}

	var reqAuthorityLevel rhine.AuthorityLevel
	reqAuthorityLevel = rhine.AuthorityLevel(authl)

	// Make a new ZoneManager
	nzm := rhine.NewZoneManager(cof)

	if nzm == nil {
		return
	}

	// Make a new Csr
	csr, errcsr := nzm.CreateSignedCSR(reqAuthorityLevel, expirationTime, nzm.Ca, nzm.AggList, revocationBit)
	if errcsr != nil {
		//log.Fatalf("Creation of the csr failed! ", errcsr)
		return
	}
	log.Println("Created a signed CSR")

	// Connect to the parent
	//conn := rhine.GetGRPCConn(cof.ParentServerAddr)
	//log.Println("Established connection to Parent at: ", cof.ParentServerAddr)

	//defer conn.Close()
	c := ps.NewParentServiceClient(connec)

	// Send delegation request to the server
	ctx, _ := context.WithTimeout(context.Background(), timeout)
	r, err := c.InitDelegation(ctx, &ps.InitDelegationRequest{Rid: csr.ReturnRid(), Csr: csr.ReturnRawBytes()})
	if err != nil {
		return
		//log.Fatalf("No response from ParentServer: %v", err)
	}
	//log.Println("Received a response from parent for Delegation Req.: ", r)
	log.Println("Received a response from parent for Delegation Request")
	// Close connection
	//conn.Close()

	// Parse the response
	/*
		apv := &rhine.RhineSig{
			Data:      r.Approvalcommit.Data,
			Signature: r.Approvalcommit.Sig,
		}
	*/

	// Parse parent certificate
	/*
		pcertp, certerr := x509.ParseCertificate(r.Rcertp)
		if certerr != nil {
			return
			//log.Fatalf("Certificate Parsing failure: %v", certerr)
		}
	*/

	/*
		// Check wheter acsr is valid
		if !apv.Verify(pcertp.PublicKey) {
			return
			//log.Fatal("Checking acsr failed")
		}
	*/

	atomic.AddUint64(&counterSend, 1)

	log.Println("Parent certificate parsed and parent signed CSR is valid")
	log.Println("Forwarding response to CA for certificate request")

	// Forward response content to CA
	caacsr := &ca.RhineSig{
		Data: r.Approvalcommit.Data,
		Sig:  r.Approvalcommit.Sig,
	}

	cca := ca.NewCAServiceClient(conna)

	// Send delegation request to the  CA server
	ctxca, _ := context.WithTimeout(context.Background(), timeout)

	rCA, errca := cca.SubmitNewDelegCA(ctxca, &ca.SubmitNewDelegCARequest{Rcertp: r.Rcertp, Acsr: caacsr, Rid: csr.ReturnRid()})
	if errca != nil {
		log.Println("Request Delegation failed!")
		//log.Fatalf("Negative response from CA: %v", err)
	}
	log.Println("Received response from CA", rCA)
	atomic.AddUint64(&counterDone, 1)

	/*
		// Parse received certificate
		childce, parseerr := x509.ParseCertificate(rCA.Rcertc)
		if parseerr != nil {
			log.Fatal("Failed parsing returned RHINE cert ", parseerr)
		}

		// Last checks

		// Collect LOG_CONFIRMS
		logConfirmList := []rhine.Confirm{}
		countLCFM := 0
		inOrderKey := []any{}

		for _, lcfm := range rCA.Lcfms {
			logConf, errTranspConfL := rhine.TransportBytesToConfirm(lcfm)
			if errTranspConfL != nil {
				log.Fatalf("Could not unmarshall LOG_CONFIRM")
			}
			logConfirmList = append(logConfirmList, *logConf)
			countLCFM++

			// Create key list
			inOrderKey = append(inOrderKey, nzm.LogMap[logConf.EntityName].Pubkey)
		}
		log.Println("Received ", countLCFM, " LOG_CONFIRM(S)")

		// Check if LogConfirms are correctly signed
		if !rhine.VerifyLogConfirmSlice(logConfirmList, nzm.LogMap) {
			log.Fatalf("A LogConfirm was not correctly signed!")
		}
		log.Println("All LogConfirms checked and valid")

		// Verify certificate issuance and verify the SCT included in the certificate
		if err := rhine.VerifyEmbeddedSCTs(childce, nzm.CaCert, inOrderKey); err != nil {
			log.Fatalf("Verification of certificate included SCTs failed!")
		}
		log.Println("Certificate issued by trusted CA and included SCTs are valid.")

		// Check if issued Certificate matches our created CSR
		if !csr.CheckAgainstCert(childce) {
			log.Fatalf("Cerificate does not match Certificate Signing Request!")
		}
		log.Println("Certificate matches CSR.")

		// Check DSum and received RCert match
		// We have to remove the SCTList to make the two TBSCerts comparable
		tbsChildCert := rhine.ExtractTbsRCAndHash(childce, true)

		if bytes.Compare(logConfirmList[0].Dsum.Cert, tbsChildCert) != 0 {
			// Print parsed TBSCert from childce
			nosct, _ := x509.RemoveSCTList(childce.RawTBSCertificate)
			tbscerti, _ := x509.ParseTBSCertificate(nosct)
			log.Println(x509util.CertificateToString(tbscerti))

			log.Fatalf("Failed: DSum certificate data does not match received certificate data!")
		}
		log.Println("DSum und received RCert match")

		// Store the certificate

		if rhine.StoreCertificatePEM(OutputPath, rCA.Rcertc) != nil {
			log.Fatal("Failed storing returned RHINE cert")
		}

		// Print certificate
		log.Println(x509util.CertificateToString(childce))

		log.Println("Certificate stored")
	*/
}
