package rhine

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"time"

	"encoding/json"

	"errors"
	"io/ioutil"
	"log"

	badger "github.com/dgraph-io/badger/v3"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/components/aggregator"
)

type LogManager struct {
	Log     Log
	privkey any
	PubKey  any

	CertPool *x509.CertPool
	LogMap   map[string]Log
	AggMap   map[string]Agg
	LogList  []string
	AggList  []string
	Ca       Authority

	Dsalog       *DSALog
	T            uint64
	RequestCache map[string]RememberRequest

	CTAddress string
	CTPrefix  string

	DB *badger.DB
}

type RememberRequest struct {
	Rid        []byte
	NDS        *Nds
	PreRCc     *x509.Certificate
	ParentCert *x509.Certificate
}

type LogConfig struct {
	PrivateKeyAlgorithm string
	PrivateKeyPath      string
	ServerAddress       string
	RootCertsPath       string

	LogsName        []string
	LogsPubKeyPaths []string

	AggregatorName []string
	AggPubKeyPaths []string

	CAName       string
	CAServerAddr string
	CAPubKeyPath string

	CTAddress string
	CTPrefix  string

	KeyValueDBDirectory string
}

func LoadLogConfig(Path string) (LogConfig, error) {
	conf := LogConfig{}
	file, err := ioutil.ReadFile(Path)
	if err != nil {
		return LogConfig{}, err
	}
	if err = json.Unmarshal(file, &conf); err != nil {
		return LogConfig{}, err
	}

	return conf, nil
}

func NewLogManager(config LogConfig) *LogManager {
	if config.PrivateKeyAlgorithm == "" {
		log.Fatal("No private key alg in config")
	}
	var privKey interface{}
	var pubkey interface{}

	if config.PrivateKeyPath == "" {
		log.Fatalln("No private key path for log private key!")
	} else {
		switch config.PrivateKeyAlgorithm {
		case "RSA":
			var err error
			privKey, err = LoadRSAPrivateKeyPEM(config.PrivateKeyPath)
			if err != nil {
				log.Fatal("Error loading private key: ", err)
			}
			pubkey = privKey.(*rsa.PrivateKey).Public()
		case "Ed25519":
			var err error
			privKey, err = LoadPrivateKeyEd25519(config.PrivateKeyPath)
			if err != nil {
				log.Fatal("Error loading private key: ", err)
			}
			pubkey = privKey.(ed25519.PrivateKey).Public()
		}
	}

	var LogCertPool *x509.CertPool
	LogCertPool, err := x509.SystemCertPool()
	if err == nil {
		LogCertPool = x509.NewCertPool()
	}

	// Load CA Pubkey
	caPk, _ := PublicKeyFromFile(config.CAPubKeyPath)

	// Open database (should be created if not existing yet)
	db, errdb := badger.Open(badger.DefaultOptions(config.KeyValueDBDirectory))
	if errdb != nil {
		log.Fatal(errdb)
	}
	// TODO When is db.Close() called ?!

	mylog := LogManager{
		privkey: privKey,
		Log: Log{
			Name:   config.ServerAddress,
			Pubkey: pubkey,
		},
		Dsalog:   NewDSALog(),
		CertPool: LogCertPool,
		Ca: Authority{
			Name:   config.CAName,
			Pubkey: caPk,
		},
		CTAddress: config.CTAddress,
		CTPrefix:  config.CTPrefix,
		DB:        db,
	}

	files, err := ioutil.ReadDir(config.RootCertsPath)
	//log.Println("Files for trust root: ", files)
	if err != nil {
		log.Fatal("Error reading roots directory: ", err)
	}

	for _, file := range files {
		pemfile, _ := ioutil.ReadFile(config.RootCertsPath + file.Name())

		if mylog.CertPool.AppendCertsFromPEM(pemfile) {
			log.Println("Added " + file.Name() + " to trust root")
		}
	}

	mylog.LogMap = make(map[string]Log)
	mylog.AggMap = make(map[string]Agg)
	mylog.LogList = config.LogsName
	mylog.AggList = config.AggregatorName

	// Log map for pubkey
	for i, v := range config.LogsName {
		pk, _ := PublicKeyFromFile(config.LogsPubKeyPaths[i])
		mylog.LogMap[v] = Log{
			Name:   v,
			Pubkey: pk,
		}
	}

	// Aggr map for pubkey
	for i, v := range config.AggregatorName {
		pk, _ := PublicKeyFromFile(config.AggPubKeyPaths[i])
		mylog.AggMap[v] = Agg{
			Name:   v,
			Pubkey: pk,
		}
	}

	// Start up RequestCache
	mylog.RequestCache = make(map[string]RememberRequest)

	return &mylog

}

func (lm *LogManager) DSProof(pzone string, czone string) (Dsp, error) {
	dsp, err := lm.Dsalog.DSProofRet(pzone, czone, ProofOfAbsence, lm.DB)
	if err != nil {
		return Dsp{}, err
	}

	// Sign the DSProof
	(&dsp).Sign(lm.privkey)

	// TODO remove
	log.Println("DSP signature validation: ", (&dsp).Sig.Verify(lm.PubKey))

	//log.Printf("DSP in LogManager after generation %+v", dsp)
	return dsp, nil
}

func (lm *LogManager) VerifyNewDelegationRequestLog(rcertp *x509.Certificate, acsr *RhineSig, precert *x509.Certificate, nds *Nds) (error, *Psr, *Lwit) {
	psr := Psr{
		psignedcsr: *acsr,
		pcert:      rcertp,
	}

	// Check that ACSR was signed by Parent and
	// Check that the csr is signed by the Child
	// And check that child and parent are what they say
	if err := psr.Verify(lm.CertPool); err != nil {
		return err, nil, nil
	}
	log.Println("DLGT_APPROVAL correctly signed, corresponds to ParentCertificate and child-parent relationship checked.")

	// Check input against DSP from local DSA
	dsp, errdsp := lm.DSProof(psr.ParentZone, psr.ChildZone)
	if errdsp != nil {
		return errdsp, &psr, nil
	}

	log.Println("Querying local DSA")

	// Check validity of dsp
	// Check if proof is correct
	// Check if pcert matches dsp
	// Check ALC and ALP compatibility
	if !(&dsp).Verify(lm.Log.Pubkey, psr.ChildZone, rcertp, psr.GetAlFromCSR()) {
		log.Println("Verification of dsp failed")
		return errors.New("Verification of DSP failed / Checks against it failed"), nil, nil
	}

	log.Println("Local DSP valid, proof is correct, corresponds to ParentCert")

	// Check PreCert (lm.CertPool contains our trusted CA Certificates)
	if err := CheckRCertValid(precert, lm.CertPool); err != nil {
		return err, nil, nil
	}
	log.Println("PreCertificate correct.")

	// Check CSR matching PreCert
	if !psr.csr.CheckAgainstCert(precert) {
		return errors.New("PreCert and CSR not matching."), nil, nil
	}

	// Check NDS
	if !nds.CheckAgainstCSR(psr.csr) {
		log.Printf("Failed check of NDS against CSR: %+v ", nds)
		return errors.New("Failed check of NDS against CSR at log"), nil, nil
	}
	log.Println("NDS  matches CSR")

	// Check Correct Signature on NDS
	if err := nds.VerifyNDS(lm.Ca.Pubkey); err != nil {
		return err, nil, nil
	}
	log.Println("NDS correctly signed.")

	// Construct LogWitness
	lwit, errlwit := CreateLwit(nds, &lm.Log, psr.csr.logs, lm.privkey)
	if errlwit != nil {
		return errlwit, nil, nil
	}

	// Store important data in Request cache
	lm.RequestCache[string(psr.csr.rid)] = RememberRequest{
		Rid:        psr.csr.rid,
		NDS:        nds,
		PreRCc:     precert,
		ParentCert: rcertp,
	}

	log.Printf("Request cache entry: %+v", lm.RequestCache[string(psr.csr.rid)])

	return nil, &psr, lwit
}

func (lm *LogManager) FinishInitialDelegLog(dsum DSum, nds *Nds, pzone string, preRCChild *x509.Certificate) (Confirm, []byte, error) {
	retConf := Confirm{}
	aggc, err := CreateConfirm(1, nds, lm.Log.Name, dsum, lm.privkey)
	if err != nil {
		return retConf, nil, err
	}

	// SCT!
	url := "http://" + lm.CTAddress + "/" + lm.CTPrefix + "/ct/v1/add-pre-chain"
	chain := [][]byte{}
	// Append the child PreCert
	chain = append(chain, preRCChild.Raw)
	//log.Println("IS CHILD CERT PRECERT?: ", preRCChild.IsPrecertificate())

	// Append Cert to log and get a SCT!
	sct, errsct := SendPreCertToLogBackend(url, chain)
	if errsct != nil {
		return retConf, nil, errsct
	}

	if sct == nil {
		return retConf, nil, errors.New("No SCT received from Backend.")
	}

	// Serialize SCT
	// The SCT is serialized using TLS-encoding
	sctbytes, marshalerr := tls.Marshal(*sct)
	if marshalerr != nil {
		log.Println("Error during SCT marshalling: ", marshalerr)
		return retConf, nil, marshalerr
	}

	// TODO At a different time
	// Retrieve DSA from aggregator!
	lm.GetDSAfromAggregators()

	return *aggc, sctbytes, nil
}

func (lm *LogManager) GetDSAfromAggregators() {
	// Connect to the aggreg
	conn := GetGRPCConn(lm.AggList[0])
	log.Println("Established connection to Aggregator at: ", lm.AggList[0])

	defer conn.Close()
	c := aggregator.NewAggServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.DSRetrieval(ctx, &aggregator.RetrieveDSALogRequest{RequestedZones: []string{}})
	if err != nil {
		log.Fatalf("No response from Aggregator: %v", err)
	}

	//log.Println("What aggreg gave us", r.DSAPayload)

	// Add results to badger and to cache
	// TODO add to cache
	for _, bytesdsa := range r.DSAPayload {
		// Deseri
		dsares := &DSA{}
		errdeserial := DeserializeCBOR(bytesdsa, dsares)
		if errdeserial != nil {
			log.Println("Could not deseri a request")
			return
		}

		errup := lm.DB.Update(func(txn *badger.Txn) error {
			err := txn.Set([]byte(dsares.Zone), bytesdsa)
			return err
		})
		if errup != nil {
			log.Println("DSALog: Error saving new delegation to badger DB")
			return
		}

		log.Println("Logger: Added a DSA")
	}

}
