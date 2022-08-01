package rhine

import (
	"crypto/ed25519"
	"errors"

	//"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

// zone manager manages zone, can act as parent or child zone

type ZoneManager struct {
	zone    ZoneOwner
	privkey any
	Rcert   *x509.Certificate

	LogMap  map[string]Log
	AggMap  map[string]Agg
	LogList []string
	AggList []string

	Ca     Authority
	CaCert *x509.Certificate

	ChildrenKeyDirectoryPath string
}

type ZoneConfig struct {
	PrivateKeyAlgorithm string
	PrivateKeyPath      string
	CertificatePath     string
	ServerAddress       string
	ZoneName            string
	ParentServerAddr    string

	LogsName        []string
	LogsPubKeyPaths []string

	AggregatorName []string
	AggPubKeyPaths []string

	CAName            string
	CAServerAddr      string
	CACertificatePath string

	ChildrenKeyDirectoryPath string
}

func LoadZoneConfig(Path string) (ZoneConfig, error) {
	conf := ZoneConfig{}
	file, err := ioutil.ReadFile(Path)
	if err != nil {
		return ZoneConfig{}, err
	}
	if err = json.Unmarshal(file, &conf); err != nil {
		return ZoneConfig{}, err
	}

	return conf, nil
}

func NewZoneManager(config ZoneConfig) *ZoneManager {
	if config.PrivateKeyAlgorithm == "" {
		log.Fatal("No private key alg in config")
	}
	var privKey interface{}
	var pubkey interface{}
	var cert *x509.Certificate
	var certCA *x509.Certificate

	if config.PrivateKeyPath == "" {
		log.Fatalf("ZoneManager: No PrivateKey Path was set")
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

	//Load cert
	if config.CertificatePath != "" {
		var err error
		cert, err = LoadCertificatePEM(config.CertificatePath)
		if err != nil {
			log.Fatal("Error loading certificate: ", err)
		}
	}

	//Load CA cert
	if config.CACertificatePath != "" {
		var err error
		certCA, err = LoadCertificatePEM(config.CACertificatePath)
		if err != nil {
			log.Fatal("Error loading CA certificate: ", err)
		}
	}

	caPk := certCA.PublicKey

	myzone := ZoneManager{
		privkey: privKey,
		zone: ZoneOwner{
			Name:   config.ZoneName,
			Pubkey: pubkey,
		},
		Rcert: cert,
		Ca: Authority{
			Name:   config.CAName,
			Pubkey: caPk,
		},
		CaCert:                   certCA,
		ChildrenKeyDirectoryPath: config.ChildrenKeyDirectoryPath,
	}

	// Load Aggregator and Log info
	myzone.LogMap = make(map[string]Log)
	myzone.AggMap = make(map[string]Agg)
	myzone.LogList = config.LogsName
	myzone.AggList = config.AggregatorName

	// Log map for pubkey
	for i, v := range config.LogsName {
		pk, _ := PublicKeyFromFile(config.LogsPubKeyPaths[i])
		myzone.LogMap[v] = Log{
			Name:   v,
			Pubkey: pk,
		}
	}

	// Aggr map for pubkey
	for i, v := range config.AggregatorName {
		pk, _ := PublicKeyFromFile(config.AggPubKeyPaths[i])
		myzone.AggMap[v] = Agg{
			Name:   v,
			Pubkey: pk,
		}
	}

	return &myzone

}

func (zm *ZoneManager) CreateSignedCSR(authlevel AuthorityLevel, exp time.Time, ca Authority, logs []string, revo int) (*Csr, error) {
	csr := &Csr{
		zone:       zm.zone,
		ca:         ca,
		logs:       logs,
		al:         authlevel,
		exp:        exp,
		revocation: revo,
	}

	// Create RID
	if _, err := csr.createRID(); err != nil {
		return nil, err
	}

	if err := csr.Sign(zm.privkey); err != nil {
		return nil, err
	}

	//log.Printf("At the end of Signed CSR creation %+v", csr)
	return csr, nil

}

func (zm *ZoneManager) VerifyChildCSR(rawcsr []byte) (*Csr, error) {
	// checks if csr signature ok
	csr, err := VerifyCSR(rawcsr)
	if err != nil {
		return nil, err
	}

	log.Println("Signature on CSR valid")

	// check if request for valid child zone
	if ok := GetParentZone(csr.zone.Name) == zm.zone.Name; !ok {
		return nil, errors.New("csr zone " + csr.zone.Name + " is not a child zone of " + zm.zone.Name)
	}

	log.Printf("%v is a child of %s", csr.zone.Name, GetParentZone(csr.zone.Name))

	// Check if child key and saved key match (NOTE: / needs to be last char of the Path)
	// TODO: Sanitize the name!!!
	pathChildPkey := zm.ChildrenKeyDirectoryPath + csr.zone.Name + "_pub.pem"
	if _, err := os.Stat(pathChildPkey); err != nil {
		return nil, errors.New("Not a child zone of this parent!")
	}

	pKey, errKey := PublicKeyFromFile(pathChildPkey)
	if errKey != nil {
		return nil, errKey
	}
	if !EqualKeys(pKey, csr.Pkey) {
		return nil, errors.New("Public key on parent server did not match CSR public key")
	}

	log.Println("Child public key found on ParentServer")

	//log.Printf("CSR when verifying child csr %+v", csr)

	//TODO check if delegation legal??

	return csr, nil
}

/*
func (zm *ZoneManager) GenerateACSR(rawcsr []byte) (*RhineSig, error) {
	res := RhineSig{
		Data: rawcsr,
	}
	if err := res.Sign(zm.privkey); err != nil {
		return nil, err
	}

	return &res, nil
}
*/

func (zm *ZoneManager) CreatePSR(csr *Csr) *Psr {
	psr := Psr{
		csr:        csr,
		psignedcsr: RhineSig{},
		pcert:      zm.Rcert,
		dsp:        nil,
	}

	psr.psignedcsr.Data = csr.signedcsr
	psr.psignedcsr.Sign(zm.privkey)

	return &psr
}
