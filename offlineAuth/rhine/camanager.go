package rhine

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"

	//"crypto/sha256"

	//"crypto/x509"
	"encoding/json"
	//"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"

	//"strings"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

type Ca struct {
	Address       string
	PublicKey     crypto.PublicKey
	PrivateKey    crypto.PrivateKey
	CACertificate *x509.Certificate
	CertPool      *x509.CertPool
	LogMap        map[string]Log
	AggMap        map[string]Agg
	LogList       []string
	AggList       []string
}

type CaConfig struct {
	PrivateKeyAlgorithm string
	PrivateKeyPath      string
	CertificatePath     string
	ServerAddress       string
	RootCertsPath       string

	LogsName        []string
	LogsPubKeyPaths []string

	AggregatorName []string
	AggPubKeyPaths []string
}

type CAError struct {
	Code int
	Err  error
}

func (e *CAError) Error() string {
	return fmt.Sprintf("code: %s, err: %s", e.Code, e.Err)
}

func LoadCAConfig(Path string) (CaConfig, error) {
	conf := CaConfig{}
	file, err := ioutil.ReadFile(Path)
	if err != nil {
		return CaConfig{}, err
	}
	if err = json.Unmarshal(file, &conf); err != nil {
		return CaConfig{}, err
	}

	return conf, nil
}

func NewCA(config CaConfig) *Ca {
	if config.PrivateKeyAlgorithm == "" {
		log.Fatal("No private key alg in config")
	}
	var privKey interface{}
	var pubkey interface{}
	var cert *x509.Certificate

	if config.PrivateKeyPath == "" {
		log.Fatalln("CA PrivateKey path not found!")
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

	if config.CertificatePath == "" {
		/*
			certbytes, _ := CreateSelfSignedCertCA(pubkey, interface{}(privKey))
			cert, _ = x509.ParseCertificate(certbytes)
		*/
	} else {
		var err error
		cert, err = LoadCertificatePEM(config.CertificatePath)
		if err != nil {
			log.Fatal("Error loading certificate: ", err)
		}
	}

	var CaCertPool *x509.CertPool
	CaCertPool, err := x509.SystemCertPool()
	if err == nil {
		CaCertPool = x509.NewCertPool()
	}
	myca := Ca{
		PublicKey:     pubkey,
		PrivateKey:    privKey,
		CACertificate: cert,
		CertPool:      CaCertPool,
		Address:       config.ServerAddress,
	}

	files, err := ioutil.ReadDir(config.RootCertsPath)
	//log.Println("Files for trust root: ", files)
	if err != nil {
		log.Fatal("Error reading roots directory: ", err)
	}

	for _, file := range files {
		pemfile, _ := ioutil.ReadFile(config.RootCertsPath + file.Name())

		if myca.CertPool.AppendCertsFromPEM(pemfile) {
			log.Println("Added " + file.Name() + " to trust root")
		}
	}

	myca.LogMap = make(map[string]Log)
	myca.AggMap = make(map[string]Agg)
	myca.LogList = config.LogsName
	myca.AggList = config.AggregatorName

	// Log map for pubkey
	for i, v := range config.LogsName {
		pk, _ := PublicKeyFromFile(config.LogsPubKeyPaths[i])
		myca.LogMap[v] = Log{
			Name:   v,
			Pubkey: pk,
		}
	}

	// Aggr map for pubkey
	for i, v := range config.AggregatorName {
		pk, _ := PublicKeyFromFile(config.AggPubKeyPaths[i])
		myca.AggMap[v] = Agg{
			Name:   v,
			Pubkey: pk,
		}
	}

	return &myca

}

func (myca *Ca) VerifyNewDelegationRequest(rcertp *x509.Certificate, acsr *RhineSig) (bool, error, *Psr) {
	psr := Psr{
		psignedcsr: *acsr,
		pcert:      rcertp,
	}

	// Check that ACSR was signed by Parent and
	// Check that the csr is signed by the Child
	// And check that child and parent are what they say
	if err := psr.Verify(myca.CertPool); err != nil {
		return false, err, nil
	}

	return true, nil, &psr
}

func (myca *Ca) CreatePoisonedCert(psr *Psr) *x509.Certificate {

	certTemplate := x509.Certificate{
		// TODO real serial number
		SerialNumber: big.NewInt(897),
		Issuer:       myca.CACertificate.Issuer,
		Subject:      psr.csr.csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     psr.csr.exp,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{psr.csr.csr.DNSNames[0]},
	}

	certTemplate.ExtraExtensions = append(certTemplate.Extensions, pkix.Extension{
		Id:       x509.OIDExtensionCTPoison,
		Critical: true,
		Value:    asn1.NullBytes,
	})

	certbytes, _ := x509.CreateCertificate(rand.Reader, &certTemplate, myca.CACertificate, psr.csr.csr.PublicKey, myca.PrivateKey)

	cert, _ := x509.ParseCertificate(certbytes)

	//log.Printf("The following PreCert (poisoned) was issued: %+v ", cert)

	return cert

}

func (myca *Ca) CreateNDS(psr *Psr, certC *x509.Certificate) (*Nds, error) {

	// Extract list of designated loggers
	logl := psr.csr.logs

	/*
		aggl := make([]Agg, 0, len(myca.AggMap))
		for _, v := range myca.AggMap {
			aggl = append(aggl, v)
		}
	*/

	// TODO Randomly select aggregs instead of all
	aggl := myca.AggList

	ndssign := NdsToSign{
		Log:     logl,
		Agg:     aggl,
		Zone:    psr.csr.zone,
		Al:      psr.csr.al,
		TbsCert: ExtractTbsRCAndHash(certC, false),
		Exp:     psr.csr.exp,
	}

	nds := &Nds{
		Nds: ndssign,
	}

	err := nds.Sign(myca.PrivateKey)
	if err != nil {
		return nil, err
	}

	return nds, nil
}

// sct is a list of TLS-marshalled SCTs
func (myca *Ca) IssueRHINECert(precert *x509.Certificate, psr *Psr, sct [][]byte) *x509.Certificate {
	serializedSCTList := []x509.SerializedSCT{}
	for _, v := range sct {
		serializedSCTList = append(serializedSCTList, x509.SerializedSCT{Val: v})
	}

	certTemplate := x509.Certificate{
		// TODO real serial number
		SerialNumber: precert.SerialNumber,
		Issuer:       precert.Issuer,
		Subject:      precert.Subject,
		NotBefore:    precert.NotBefore,
		NotAfter:     precert.NotAfter,
		KeyUsage:     precert.KeyUsage,
		DNSNames:     precert.DNSNames,

		SCTList: x509.SignedCertificateTimestampList{
			SCTList: serializedSCTList,
		},
	}

	/*
		rhinext, _ := psr.csr.CreateCSRExtension()

		certTemplate.ExtraExtensions = append(certTemplate.ExtraExtensions, rhinext)
	*/

	certbytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, myca.CACertificate, psr.csr.csr.PublicKey, myca.PrivateKey)
	if err != nil {
		log.Println("CA: Could not create certificate: ", err)
	}

	cert, _ := x509.ParseCertificate(certbytes)

	return cert
}
