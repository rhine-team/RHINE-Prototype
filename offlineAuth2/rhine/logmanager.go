package rhine

import (
	"crypto/ed25519"
	//"crypto/rand"
	"crypto/rsa"

	//"crypto/sha256"

	//"crypto/x509"
	"encoding/json"
	//"errors"
	"errors"
	"io/ioutil"
	"log"

	//"strings"

	//ct "github.com/google/certificate-transparency-go"
	//"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	//"github.com/google/certificate-transparency-go/x509/pkix"
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
}

type RememberRequest struct {
	Rid    []byte
	NDS    *Nds
	PreRCc *x509.Certificate
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

func (lm *LogManager) DSProof(pzone string, czone string) Dsp {
	dsp := lm.Dsalog.DSProofRet(pzone, czone, ProofOfAbsence)
	(&dsp).Sign(lm.privkey)

	//log.Printf("DSP in LogManager after generation %+v", dsp)
	return dsp
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

	// Check input against DSP from local DSA
	dsp := lm.DSProof(psr.ParentZone, psr.ChildZone)

	// Check validity of dsp
	// Check if proof is correct
	// Check if pcert matches dsp
	// Check ALC and ALP compatibility
	if !(&dsp).Verify(lm.Log.Pubkey, psr.ChildZone, rcertp, psr.GetAlFromCSR()) {
		log.Println("Verification of dsp failed")
		return errors.New("Verification of DSP failed / Checks against it failed"), nil, nil
	}

	// Check PreCert (lm.CertPool contains our trusted CA Certificates)
	if err := CheckRCertValid(precert, lm.CertPool); err != nil {
		return err, nil, nil
	}
	// TODO CSR PReRC?

	// Check NDS
	if !nds.CheckAgainstCSR(psr.csr) {
		log.Printf("Failed check of NDS against CSR: %+v ", nds)
		return errors.New("Failed check of NDS against CSR at log"), nil, nil
	}
	// Check Correct Signature on NDS
	if err := nds.VerifyNDS(lm.Ca.Pubkey); err != nil {
		return err, nil, nil
	}

	// Construct LogWitness
	lwit, errlwit := CreateLwit(nds, &lm.Log, psr.csr.logs, lm.privkey)
	if errlwit != nil {
		return errlwit, nil, nil
	}

	// Store important data in Request cache
	lm.RequestCache[string(psr.csr.rid)] = RememberRequest{
		Rid:    psr.csr.rid,
		NDS:    nds,
		PreRCc: precert,
	}

	log.Printf("Request cache entry: %+v", lm.RequestCache[string(psr.csr.rid)])

	return nil, &psr, lwit
}

func (lm *LogManager) FinishInitialDelegLog(dsum DSum, nds *Nds) (Confirm, []byte, error) {
	retConf := Confirm{}
	aggc, err := CreateConfirm(1, nds, lm.Log.Name, dsum, lm.privkey)
	if err != nil {
		return retConf, nil, err
	}

	return *aggc, []byte{}, nil
}

/*
func (lm *LogManager) ConstructSCT(PreRC *x509.Certificate) *ct.SignedCertificateTimestamp {
	res := &ct.SignedCertificateTimestamp{
		// SCTVersion
		// LogID
		// Timestamp
		//Extenstions

	}
}
*/

/*
func (lm LogManager) DSProofRetOld(PZone string, CZone string, ptype MPathProofType) Dsp {
	log := lm.logs[PZone]

	dsp := Dsp{
		dsum:   log.GetDSum(),
		epochT: lm.T,
		sig:    RhineSig{},
		proof:  MPathProof{},
	}

	dsp.Sign(lm.privkey)

	var path [][]byte
	switch ptype {
	case ProofOfPresence:
		path, _, _ = lm.GetInclusionProof(PZone, CZone)
	case ProofOfAbsence:
		path, _, _ = lm.GetAbsenceProof(PZone, CZone)
	}

	dsp.proof = MPathProof{
		path:  path,
		ptype: ptype,
	}

	return dsp
}

/*
func (lm LogManager) GetInclusionProof(zone string, label string) (merklepath [][]byte, index []int64, err error) {

	log := lm.logs[zone]

	for _, leaf := range log.subzones {
		if leaf.start.zone == label || leaf.end.zone == label {
			merklepath, index, err = log.acc.GetMerklePath(leaf)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, errors.New("label not found")
}

func (lm LogManager) GetAbsenceProof(zone string, label string) (merklepath [][]byte, index []int64, err error) {

	log := lm.logs[zone]

	for _, leaf := range log.subzones {
		if strings.Compare(leaf.start.zone, label) == -1 && strings.Compare(leaf.end.zone, label) == 1 {
			merklepath, index, err = log.acc.GetMerklePath(leaf)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, errors.New("label not found")
}
*/
