package rhine

import (
	"errors"
	//"log"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
	"log"
	"time"

	"github.com/google/certificate-transparency-go/x509"
)

// zone manager manages zone, can act as parent or child zone

type ZoneManager struct {
	zone    ZoneOwner
	privkey any
	rcert   *x509.Certificate
}

type ZoneConfig struct {
	PrivateKeyAlgorithm string
	PrivateKeyPath      string
	CertificatePath     string
	ServerAddress       string
	ZoneName            string
	ParentServerAddr    string
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

	if config.PrivateKeyPath == "" {
		switch config.PrivateKeyAlgorithm {
		case "RSA":
			privKey, _ = rsa.GenerateKey(rand.Reader, 2048)
			pubkey = privKey.(*rsa.PrivateKey).Public()
		case "Ed25519":
			pubkey, privKey, _ = ed25519.GenerateKey(rand.Reader)
		}
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
	if config.CertificatePath == "" {

	} else {
		var err error
		cert, err = LoadCertificatePEM(config.CertificatePath)
		if err != nil {
			log.Fatal("Error loading certificate: ", err)
		}
	}

	myzone := ZoneManager{
		privkey: privKey,
		zone: ZoneOwner{
			Name:   config.ZoneName,
			Pubkey: pubkey,
		},
		rcert: cert,
	}

	return &myzone

}

func (zm *ZoneManager) CreateSignedCSR(authlevel AuthorityLevel, exp time.Time, ca Authority, log []Log, revo int) (*Csr, error) {
	csr := Csr{
		zone:       zm.zone,
		ca:         ca,
		log:        log,
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

	return &csr, nil

}

func (zm *ZoneManager) VerifyChildCSR(rawcsr []byte) (*Csr, error) {
	// checks if csr signature ok
	csr, err := VerifyCSR(rawcsr)
	if err != nil {
		return nil, err
	}

	// check if request for valid child zone
	if ok := GetParentZone(csr.zone.Name) == zm.zone.Name; !ok {
		return nil, errors.New("csr zone " + csr.zone.Name + " is not a child zone of " + zm.zone.Name)
	}

	//TODO check if delegation legal??

	// Generate apv

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
		pcert:      zm.rcert,
		dsp:        nil,
	}

	psr.psignedcsr.Data = csr.signedcsr
	psr.psignedcsr.Sign(zm.privkey)

	return &psr
}
