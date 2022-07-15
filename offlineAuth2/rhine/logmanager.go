package rhine

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"

	//"crypto/sha256"

	//"crypto/x509"
	"encoding/json"
	//"errors"
	"io/ioutil"
	"log"

	//"strings"

	//ct "github.com/google/certificate-transparency-go"
	//"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	//"github.com/google/certificate-transparency-go/x509/pkix"
)

type LogManager struct {
	Log          Log
	privkey      any
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

	mylog := LogManager{
		privkey: privKey,
		Log: Log{
			Name:   config.ServerAddress,
			Pubkey: pubkey,
		},
		Dsalog: NewDSALog(),
	}

	return &mylog

}

func (lm *LogManager) DSProof(pzone string, czone string) Dsp {
	dsp := lm.Dsalog.DSProofRet(pzone, czone, ProofOfAbsence)
	(&dsp).Sign(lm.privkey)
	return dsp
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
