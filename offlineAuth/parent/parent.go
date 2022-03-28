package parent

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	logger15 "github.com/inconshreveable/log15"
	"github.com/rhine-team/RHINE-Prototype/common"
	"github.com/rhine-team/RHINE-Prototype/requests"
	"io/ioutil"
	"log"
	"net/http"
)

var logger = logger15.New("Module", "Parent")

type Parent struct {
	PublicKey            interface{}
	PrivateKey           interface{}
	AuthenticationType   string
	Certificate          *x509.Certificate
	keyType              string
	LogCheckerExtAddress string
	CAAddress            string
	OutputDir            string
}

func NewParent(config Config) *Parent {
	if config.PrivateKeyAlgorithm == "" {
		return nil
	}
	if config.Zone == "" {
		return nil
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
			privKey, err = common.LoadRSAPrivateKeyPEM(config.PrivateKeyPath)
			if err != nil {
				log.Fatal(err)
			}
			pubkey = privKey.(*rsa.PrivateKey).Public()
		case "Ed25519":
			var err error
			privKey, err = common.LoadPrivateKeyEd25519(config.PrivateKeyPath)
			if err != nil {
				log.Fatal(err)
			}
			pubkey = privKey.(ed25519.PrivateKey).Public()
		}
	}

	if config.CertificatePath == "" && config.AuthenticationType == "certificate" {
		certbytes, _ := common.CreateSelfSignedCert(pubkey, interface{}(privKey), config.Zone)
		cert, _ = x509.ParseCertificate(certbytes)
	} else if config.AuthenticationType == "certificate" {
		var err error
		cert, err = common.LoadCertificatePEM(config.CertificatePath)
		if err != nil {
			log.Fatal(err)
		}
	}

	par := Parent{
		PublicKey:            pubkey,
		PrivateKey:           privKey,
		AuthenticationType:   config.AuthenticationType,
		Certificate:          cert,
		keyType:              config.PrivateKeyAlgorithm,
		LogCheckerExtAddress: config.LogCheckerExtAddress,
		CAAddress:            config.CAAddress,
		OutputDir:            config.OutputDir,
	}

	return &par

}

func LoadConfig(Path string) (Config, error) {
	conf := Config{}
	file, err := ioutil.ReadFile(Path)
	if err != nil {
		return Config{}, err
	}
	if err = json.Unmarshal(file, &conf); err != nil {
		return Config{}, err
	}

	return conf, nil
}

func (p *Parent) NewDlg(csrbytes []byte, IndSubZone bool) ([]byte, error) {
	logger.Info("Parent: Creating NewDlg Request")
	var IndSubZoneString string
	if IndSubZone {
		IndSubZoneString = "yes"
	} else {
		IndSubZoneString = "no"
	}
	payload := requests.NewDlgPayload{
		Req_type:           "NewDlgReq",
		IndependentSubZone: IndSubZoneString,
		Csr:                common.EncodeBase64(csrbytes),
	}

	parentRequest, _ := p.BuildNewDlgRequest(payload)

	parentRequest.Signature = p.SignNewDlgRequest(parentRequest)

	resp, err := p.PostNewDlgRequest(parentRequest)
	if err != nil {
		return nil, err
	}

	if resp.Cert == "" {
		return nil, errors.New("Error from CA: " + resp.Error)
	}

	certbytes, _ := common.DecodeBase64(resp.Cert)
	// TODO need protection from malicious CA here. CA could have signed cert for different zone
	// TODO if no checks, Parent helps CA to put bogus cert in log!
	// TODO check also that requested CA signed it
	// TODO function CsrCertMatch(csrbytes, certbytes) check Key, dns name, ..
	err = CheckCSRCertMatch(csrbytes, certbytes)
	if err != nil {
		return nil, err
	}

	logger.Info("Parent: Creating Checker Extension Request")
	checkerReq := p.BuildCheckNewDlgReq(certbytes)
	checkerReq.Signature = p.SignCheckNewDlgRequest(checkerReq)
	checkResp, err := p.PostCheckNewDlgReq(checkerReq)
	if err != nil {
		logger.Warn("Parent: Checker Request FAILED")
		return nil, err
	}

	if checkResp.Status != "OK" {
		logger.Warn("Parent: Checker Error: " + checkResp.Error)
		return nil, errors.New(checkResp.Error)
	}

	logger.Info("Parent: Checker Request OK")
	return certbytes, nil
}

func CheckCSRCertMatch(csrbytes []byte, certbytes []byte) error {
	csr, err := x509.ParseCertificateRequest(csrbytes)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(certbytes)
	if err != nil {
		return err
	}

	match := true

	switch csr.PublicKey.(type) {
	case *rsa.PublicKey:
		csrKey, _ := csr.PublicKey.(*rsa.PublicKey)
		if !csrKey.Equal(cert.PublicKey) {
			match = false
		}
	case ed25519.PublicKey:
		csrKey, _ := csr.PublicKey.(ed25519.PublicKey)
		if !csrKey.Equal(cert.PublicKey) {
			match = false
		}
	default:
		match = false
	}
	for i, name := range csr.DNSNames {
		if !(name == cert.DNSNames[i]) {
			match = false
		}
	}

	if !match {
		return errors.New("CA Signed Certificate and CSR do not match")
	}

	return nil

}

func (p *Parent) BuildNewDlgRequest(payload requests.NewDlgPayload) (requests.NewDlgRequest, error) {
	var parentCert string
	if p.Certificate != nil {
		parentCert = common.EncodeBase64(p.Certificate.Raw)
	} else {
		parentCert = ""
	}

	//fmt.Println(reflect.TypeOf(p.PublicKey))
	parentPublicKey, _, err := common.EncodePublicKey(p.PublicKey)
	if err != nil {
		return requests.NewDlgRequest{}, err
	}

	parentRequest := requests.NewDlgRequest{
		Header: &requests.ParentHeader{
			Parent_auth_type: p.AuthenticationType,
			Parent_cert:      parentCert,
			Alg:              p.keyType,
			Pubkey:           parentPublicKey,
		},
		Payload:   &payload,
		Signature: "",
	}

	return parentRequest, nil
}

func (p *Parent) SignNewDlgRequest(req requests.NewDlgRequest) string {
	headerSig, _ := json.Marshal(req.Header)
	payloadSig, _ := json.Marshal(req.Payload)
	sigbytes := []byte{}

	switch p.keyType {
	case "Ed25519":
		sigbytes = ed25519.Sign(p.PrivateKey.(ed25519.PrivateKey), append(headerSig, payloadSig...))
	case "RSA":
		sha256 := sha256.New()
		sha256.Write(append(headerSig, payloadSig...))
		hash := sha256.Sum(nil)
		sigbytes, _ = rsa.SignPSS(rand.Reader, p.PrivateKey.(*rsa.PrivateKey), crypto.SHA256, hash, nil)
	default:
		return ""
	}

	encodedSig := common.EncodeBase64(sigbytes)
	return encodedSig
}

func (p *Parent) PostNewDlgRequest(req requests.NewDlgRequest) (requests.CAResponse, error) {
	jsonreq, _ := json.Marshal(req)
	address := "http://" + p.CAAddress + "/NewDlg" // TODO change to https

	log.Printf("Posting Request: %#v\n", req)
	resp, err := http.Post(address, "application/json", bytes.NewReader(jsonreq))
	if err != nil {
		return requests.CAResponse{}, err
	}
	defer resp.Body.Close()

	var caResp requests.CAResponse
	err = json.NewDecoder(resp.Body).Decode(&caResp)
	log.Printf("Response: %#v\n", caResp)

	if err != nil {
		return requests.CAResponse{}, err
	}
	return caResp, nil
}

func (p *Parent) BuildCheckNewDlgReq(cert []byte) requests.CheckNewDlgRequest {
	var parentCert string
	if p.Certificate != nil {
		parentCert = common.EncodeBase64(p.Certificate.Raw)
	} else {
		parentCert = ""
	}
	parentPublicKey, _, _ := common.EncodePublicKey(p.PublicKey)

	req := requests.CheckNewDlgRequest{
		Header: &requests.ParentHeader{
			Parent_auth_type: p.AuthenticationType,
			Parent_cert:      parentCert,
			Pubkey:           parentPublicKey,
			Alg:              p.keyType,
		},
		Payload: &requests.CheckNewDlgPayload{
			Cert: common.EncodeBase64(cert),
		},
		Signature: "",
	}

	return req
}

func (p *Parent) SignCheckNewDlgRequest(req requests.CheckNewDlgRequest) string {
	headerSig, _ := json.Marshal(req.Header)
	payloadSig, _ := json.Marshal(req.Payload)
	sigbytes := []byte{}

	switch p.keyType {
	case "Ed25519":
		sigbytes = ed25519.Sign(p.PrivateKey.(ed25519.PrivateKey), append(headerSig, payloadSig...))
	case "RSA":
		sha256 := sha256.New()
		sha256.Write(append(headerSig, payloadSig...))
		hash := sha256.Sum(nil)
		sigbytes, _ = rsa.SignPSS(rand.Reader, p.PrivateKey.(*rsa.PrivateKey), crypto.SHA256, hash, nil)
	default:
		return ""
	}
	encodedSig := common.EncodeBase64(sigbytes)
	return encodedSig
}

func (p *Parent) PostCheckNewDlgReq(req requests.CheckNewDlgRequest) (requests.CheckResponse, error) {
	jsonreq, _ := json.Marshal(req)
	address := "http://" + p.LogCheckerExtAddress + "/CheckNewDlg" // TODO change to https
	resp, err := http.Post(address, "application/json", bytes.NewReader(jsonreq))
	if err != nil {
		fmt.Println(err)
	}
	defer resp.Body.Close()

	var checkResp requests.CheckResponse
	err = json.NewDecoder(resp.Body).Decode(&checkResp)
	log.Printf("Response: %#v\n", checkResp)

	if err != nil {
		return requests.CheckResponse{}, err
	}
	return checkResp, nil

}