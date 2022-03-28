package ca

import (
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
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/rainsclientlog"
	"github.com/rhine-team/RHINE-Prototype/requests"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

var logger = logger15.New("Module", "CA")

// var loggerNewDlg = logger.New("Request", "NewDlg") //TODO make logger for every request

type CA interface { // TODO implement interface
	ProcessNewDlgRequest(preq requests.NewDlgRequest) ([]byte, bool, *CAError)
	IssueCertificate(csr *x509.CertificateRequest) ([]byte, error)
}

type Ca struct {
	Address           string
	PublicKey         crypto.PublicKey
	PrivateKey        crypto.PrivateKey
	CACertificate     *x509.Certificate
	MapServerAddr     string
	MapServerPkeyPath string
	mapID             int64
	CertPool          *x509.CertPool
}

type CAError struct {
	Code int
	Err  error
}

func (e *CAError) Error() string {
	return fmt.Sprintf("code: %s, err: %s", e.Code, e.Err)
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

func NewCA(config Config) *Ca {
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
			privKey, err = common.LoadRSAPrivateKeyPEM(config.PrivateKeyPath)
			if err != nil {
				log.Fatal("Error loading private key: ", err)
			}
			pubkey = privKey.(*rsa.PrivateKey).Public()
		case "Ed25519":
			var err error
			privKey, err = common.LoadPrivateKeyEd25519(config.PrivateKeyPath)
			if err != nil {
				log.Fatal("Error loading private key: ", err)
			}
			pubkey = privKey.(ed25519.PrivateKey).Public()
		}
	}

	if config.CertificatePath == "" {
		certbytes, _ := common.CreateSelfSignedCertCA(pubkey, interface{}(privKey))
		cert, _ = x509.ParseCertificate(certbytes)
	} else {
		var err error
		cert, err = common.LoadCertificatePEM(config.CertificatePath)
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
		PublicKey:         pubkey,
		PrivateKey:        privKey,
		CACertificate:     cert,
		MapServerAddr:     config.MapServerAddress,
		MapServerPkeyPath: config.MapServerPublicKeyPath,
		mapID:             config.MapId,
		CertPool:          CaCertPool,
		Address:           config.ServerAddress,
	}

	files, err := ioutil.ReadDir(config.RootCertsPath)
	if err != nil {
		log.Fatal("Error reading roots directory: ", err)
	}

	for _, file := range files {
		pemfile, _ := ioutil.ReadFile(config.RootCertsPath + file.Name())
		if myca.CertPool.AppendCertsFromPEM(pemfile) {
			logger.Warn("Added " + file.Name() + " to trust root")
		}
	}

	return &myca

}

func (myca *Ca) ProcessNewDlgRequest(preq requests.NewDlgRequest) ([]byte, *CAError) {
	logger.Info("CA: Processing NewDlg Request")
	csrbytes, err := common.DecodeBase64(preq.Payload.Csr)
	if err != nil {
		return nil, &CAError{
			Code: requests.CsrDecodeError,
			Err:  err,
		}
	}
	csr, err := x509.ParseCertificateRequest(csrbytes)
	if err != nil {
		return nil, &CAError{
			Code: requests.CsrParseError,
			Err:  err,
		}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, &CAError{
			Code: requests.CsrSignatureInvalid,
			Err:  err,
		}
	}
	var childzone string
	if len(csr.DNSNames) > 0 {
		childzone = csr.DNSNames[0]
	} else {
		return nil, &CAError{
			Code: requests.CsrSANDNSMissing,
			Err:  errors.New(requests.ErrorMsg[requests.CsrSANDNSMissing]),
		}
	}

	logger.Info("Parsed CSR", "zone", childzone)

	parentzone := common.GetParentZone(childzone)
	var publicKey interface{}

	// parent authentication
	switch preq.Header.Parent_auth_type {

	case "NOAUTH":
		// TODO REMOVE
		// only for testing
		logger.Crit("NO PARENT AUTHENTICATION TYPE (TESTING)")
		publicKey, _ = common.DecodePublicKey(preq.Header.Pubkey, preq.Header.Alg)

	case "dnssec":
		logger.Info("CA: Authenticating Parent: DNSSEC")
		var err error
		switch preq.Header.Alg {
		case "RSA":
			publicKey, err = common.QueryDNSKeyRSA(parentzone)
		case "Ed25519":
			publicKey, err = common.QueryDNSKeyEd25519(parentzone)
		}
		if err != nil {
			return nil, &CAError{
				Code: requests.ParentAuthDNSSECFailed,
				Err:  err,
			}
		}
		logger.Info("CA: Authenticated Parent DNSSEC")

	case "certificate":
		logger.Info("CA: Authenticating Parent: Certificate")
		certbytes, err := common.DecodeBase64(preq.Header.Parent_cert)
		if err != nil {
			return nil, &CAError{
				Code: requests.ParentAuthCertDecodeError,
				Err:  err,
			}
		}
		cert, err := x509.ParseCertificate(certbytes)
		if err != nil {
			return nil, &CAError{
				Code: requests.ParentAuthCertParseError,
				Err:  err,
			}
		}
		if cert != nil {
			publicKey = cert.PublicKey
		} else {
			return nil, &CAError{
				Code: requests.ParentAuthCertParseError,
				Err:  errors.New("Public Key in Certificate missing"),
			}
		}
		parentlogcerts, err := rainsclientlog.QueryMapServerZoneInfo(parentzone, myca.mapID, myca.MapServerAddr, myca.MapServerPkeyPath)
		if err != nil {
			return nil, &CAError{
				Code: requests.MapServerConnectionFailed,
				Err:  err,
			}
		}
		validParentCerts := myca.FilterValidCertsFromChains(parentlogcerts, parentzone)

		if _, ok, err := myca.VerifyParentCertificate(validParentCerts, cert, parentzone); !ok {
			return nil, &CAError{
				Code: requests.ParentAuthCertInvalid,
				Err:  err,
			}
		}
		logger.Info("CA: Parent Certificate Verified")
	default:
		return nil, &CAError{
			Code: requests.AuthTypeMissing,
			Err:  errors.New(requests.ErrorMsg[requests.AuthTypeMissing]),
		}
	}

	// signature verification
	if ok, err := VerifyNewDlgReqSignature(preq, publicKey); ok {
	} else {
		return nil, &CAError{
			Code: requests.InvalidSignature,
			Err:  err,
		}
	}
	logger.Info("CA: Parent Signature Verified")

	// TODO check what logcerts double list exactly returns and how to check if no conflicting certs found
	// returns a list of certchains ( = list of certs, with chain bottom being index 0) => we are looking for [0][0], [1][0], ...
	//TODO do for every DNS name in csr not just first
	logcerts, err := rainsclientlog.QueryMapServerZoneInfo(childzone, myca.mapID, myca.MapServerAddr, myca.MapServerPkeyPath)
	if err != nil {
		return nil, &CAError{
			Code: requests.MapServerConnectionFailed,
			Err:  err,
		}
	}

	validCerts := myca.FilterValidCertsFromChains(logcerts, childzone)
	logger.Info(fmt.Sprintf("%d valid unrevoked certificates received from log", len(validCerts)))

	independentvalidCerts := common.FilterIndependentZoneCerts(validCerts)
	logger.Info(fmt.Sprintf("%d valid unrevoked certificates for independent zones received from log", len(independentvalidCerts)))

	if len(independentvalidCerts) != 0 {
		return nil, &CAError{
			Code: requests.ConflictingCertInLog,
			Err:  errors.New(requests.ErrorMsg[requests.ConflictingCertInLog]),
		}
	}

	// creating certificate
	// TODO: check csr for CA public key or ID
	var IndependentSubZone bool
	switch strings.ToLower(preq.Payload.IndependentSubZone) {
	case "yes":
		IndependentSubZone = true
	case "no":
		IndependentSubZone = false
	default:
		IndependentSubZone = false
	}

	certbytes, err := myca.IssueCertificate(csr, IndependentSubZone)
	if err != nil {
		return nil, &CAError{
			Code: requests.CertIssueError,
			Err:  err,
		}
	}
	logger.Info("CA: Issued Certificate")
	return certbytes, nil
}

func (myca *Ca) ProcessReNewDlgRequest(preq requests.ReNewDlgRequest) ([]byte, *CAError) {
	logger.Info("CA: Processing ReNewDlg Request")
	csrbytes, err := common.DecodeBase64(preq.Csr)
	if err != nil {
		return nil, &CAError{
			Code: requests.CsrDecodeError,
			Err:  err,
		}
	}
	csr, err := x509.ParseCertificateRequest(csrbytes)
	if err != nil {
		return nil, &CAError{
			Code: requests.CsrParseError,
			Err:  err,
		}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, &CAError{
			Code: requests.CsrSignatureInvalid,
			Err:  err,
		}
	}
	var childzone string
	if len(csr.DNSNames) > 0 {
		childzone = csr.DNSNames[0]
	} else {
		return nil, &CAError{
			Code: requests.CsrSANDNSMissing,
			Err:  errors.New(requests.ErrorMsg[requests.CsrSANDNSMissing]),
		}
	}

	// TODO check what logcerts double list exactly returns and how to check if no conflicting certs found
	// returns a list of certchains ( = list of certs, with chain bottom being index 0) => we are looking for [0][0], [1][0], ...
	logcerts, err := rainsclientlog.QueryMapServerZoneInfo(childzone, myca.mapID, myca.MapServerAddr, myca.MapServerPkeyPath)
	if err != nil {
		return []byte{}, &CAError{
			Code: requests.MapServerConnectionFailed,
			Err:  err,
		}
	}

	validCerts := myca.FilterValidCertsFromChains(logcerts, childzone)

	ok, IsIndZone := CheckForExistingCert(validCerts, *csr)
	if !ok {
		return nil, &CAError{
			Code: requests.RequiredCertNotInLog,
			Err:  errors.New(requests.ErrorMsg[requests.RequiredCertNotInLog]),
		}
	}

	// creating certificate
	// TODO: check csr for CA public key or ID
	certbytes, err := myca.IssueCertificate(csr, IsIndZone)
	if err != nil {
		return nil, &CAError{
			Code: requests.CertIssueError,
			Err:  err,
		}
	}
	logger.Info("CA: Issued Certificate")
	return certbytes, nil
}

func (myca *Ca) ProcessKeyChangeDlgRequest(preq requests.KeyChangeDlgRequest) ([]byte, *CAError) {
	logger.Info("CA: Processing KeyChangeDlg Request")
	csrbytes, err := common.DecodeBase64(preq.Csr)
	if err != nil {
		return nil, &CAError{
			Code: requests.CsrDecodeError,
			Err:  err,
		}
	}
	csr, err := x509.ParseCertificateRequest(csrbytes)
	if err != nil {
		return nil, &CAError{
			Code: requests.CsrParseError,
			Err:  err,
		}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, &CAError{
			Code: requests.CsrSignatureInvalid,
			Err:  err,
		}
	}
	var childzone string
	if len(csr.DNSNames) > 0 {
		childzone = csr.DNSNames[0]
	} else {
		return nil, &CAError{
			Code: requests.CsrSANDNSMissing,
			Err:  errors.New(requests.ErrorMsg[requests.CsrSANDNSMissing]),
		}
	}

	// TODO check what logcerts double list exactly returns and how to check if no conflicting certs found
	// returns a list of certchains ( = list of certs, with chain bottom being index 0) => we are looking for [0][0], [1][0], ...
	logcerts, err := rainsclientlog.QueryMapServerZoneInfo(childzone, myca.mapID, myca.MapServerAddr, myca.MapServerPkeyPath)
	if err != nil {
		return nil, &CAError{
			Code: requests.MapServerConnectionFailed,
			Err:  err,
		}
	}

	validCerts := myca.FilterValidCertsFromChains(logcerts, childzone)

	var oldPublicKey interface{}
	oldPublicKey, err = common.DecodePublicKey(preq.OldKey, preq.OldKeyAlg)
	if err != nil {
		return nil, &CAError{
			Code: requests.OldKeyDecodeError,
			Err:  err,
		}
	}

	ok, IsIndZone := CheckForExistingCertKeyChange(validCerts, *csr, oldPublicKey)
	if !ok {
		return nil, &CAError{
			Code: requests.RequiredCertNotInLog,
			Err:  errors.New(requests.ErrorMsg[requests.RequiredCertNotInLog]),
		}
	}

	if ok, err := VerifyKeyChangeSignature(preq, oldPublicKey); !ok {
		return nil, &CAError{
			Code: requests.InvalidSignature,
			Err:  err,
		}
	}

	// creating certificate
	// TODO: check csr for CA public key or ID
	certbytes, err := myca.IssueCertificate(csr, IsIndZone)
	if err != nil {
		return nil, &CAError{
			Code: requests.CertIssueError,
			Err:  err,
		}
	}
	logger.Info("CA: Issued Certificate")
	return certbytes, nil
}

func VerifyKeyChangeSignature(req requests.KeyChangeDlgRequest, publicKey interface{}) (bool, error) {
	message, err := common.DecodeBase64(req.Csr)
	if err != nil {
		return false, err
	}

	sha256 := sha256.New()
	sha256.Write(message)
	digest := sha256.Sum(nil)

	byteSig := []byte{}
	byteSig, err = common.DecodeBase64(req.Signature)
	if err != nil {
		fmt.Println("error decoding b64 signature", err)
	}

	switch publicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA256, digest, byteSig, nil)
		if err != nil {
			logger.Warn("signature error")
			return false, err
		}
		return true, nil
	case ed25519.PublicKey:
		if !ed25519.Verify(publicKey.(ed25519.PublicKey), message, byteSig) {
			logger.Warn("signature error")
			return false, err
		}
		return true, nil
	default:
		return false, errors.New("unsupported key")
	}
}

func CheckForExistingParentCert(logcerts []x509.Certificate, pcert x509.Certificate) bool {
	for _, cert := range logcerts {
		switch pcert.PublicKey.(type) {
		case *rsa.PublicKey:
			csrKey, _ := pcert.PublicKey.(*rsa.PublicKey)
			if !csrKey.Equal(cert.PublicKey) {
				continue
			}
		case ed25519.PublicKey:
			csrKey, _ := pcert.PublicKey.(ed25519.PublicKey)
			if !csrKey.Equal(cert.PublicKey) {
				continue
			}
		default:
			continue
		}
		// TODO could make it only 1 name needs to match instead of all
		for i, name := range pcert.DNSNames {
			if !(name == cert.DNSNames[i]) {
				continue
			}
		}
		return true
	}
	return false
}

func CheckForExistingCert(certs []x509.Certificate, csr x509.CertificateRequest) (bool, bool) {
	for _, cert := range certs {
		switch csr.PublicKey.(type) {
		case *rsa.PublicKey:
			csrKey, _ := csr.PublicKey.(*rsa.PublicKey)
			if !csrKey.Equal(cert.PublicKey) {
				continue
			}
		case ed25519.PublicKey:
			csrKey, _ := csr.PublicKey.(ed25519.PublicKey)
			if !csrKey.Equal(cert.PublicKey) {
				continue
			}
		default:
			continue
		}
		for i, name := range csr.DNSNames {
			if !(name == cert.DNSNames[i]) {
				continue
			}
		}
		IsIndependentZone, _ := common.CheckIndFlagX509Cert(cert)
		return true, IsIndependentZone
	}
	return false, false
}

func CheckForExistingCertKeyChange(certs []x509.Certificate, csr x509.CertificateRequest, pubKey interface{}) (bool, bool) {
	for _, cert := range certs {
		switch pubKey.(type) {
		case *rsa.PublicKey:
			csrKey, _ := pubKey.(*rsa.PublicKey)
			if !csrKey.Equal(cert.PublicKey) {
				continue
			}
		case ed25519.PublicKey:
			csrKey, _ := pubKey.(ed25519.PublicKey)
			if !csrKey.Equal(cert.PublicKey) {
				continue
			}
		}
		for i, name := range csr.DNSNames {
			if !(name == cert.DNSNames[i]) {
				continue
			}
		}
		IsIndependentZone, _ := common.CheckIndFlagX509Cert(cert)
		return true, IsIndependentZone
	}
	return false, false
}

func (myca *Ca) FilterValidCertsFromChains(certchains [][]x509.Certificate, zone string) []x509.Certificate {
	var validCerts []x509.Certificate
	for _, certchain := range certchains {
		cert := certchain[0]
		if _, err := cert.Verify(x509.VerifyOptions{
			DNSName:                   zone,
			Intermediates:             nil,
			Roots:                     myca.CertPool,
			CurrentTime:               time.Time{},
			KeyUsages:                 nil,
			MaxConstraintComparisions: 0,
		}); err == nil {
			validCerts = append(validCerts, cert)
		}
	}
	return validCerts
}

func (myca *Ca) IssueCertificate(csr *x509.CertificateRequest, IsIndependentSubzone bool) ([]byte, error) {

	RhineExt, _ := common.CreateIndFlagExt(IsIndependentSubzone)

	certTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(123),
		Issuer:                myca.CACertificate.Issuer,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 356),
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		DNSNames:              []string{csr.DNSNames[0]},
	}
	certTemplate.ExtraExtensions = append(certTemplate.ExtraExtensions, RhineExt)

	certbytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, myca.CACertificate, csr.PublicKey, myca.PrivateKey)
	if err != nil {
		return []byte{}, err
	}
	return certbytes, nil
}

func DecodeNewDlgRequest(r *http.Request) (*requests.NewDlgRequest, *CAError) {
	// TODO more checks
	var req requests.NewDlgRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, &CAError{
			Code: requests.JSONDecodeError,
			Err:  err,
		}
	}
	if req.Header.Parent_auth_type == "certificate" && req.Header.Parent_cert == "" {
		return nil, &CAError{
			Code: requests.ParentCertificateMissing,
			Err:  errors.New(requests.ErrorMsg[requests.ParentCertificateMissing]),
		}
	}
	if req.Header.Parent_auth_type == "dnssec" && !(req.Header.Alg == "RSA" || req.Header.Alg == "Ed25519") {
		return nil, &CAError{
			Code: requests.UnsupportedAlg,
			Err:  errors.New(requests.ErrorMsg[requests.UnsupportedAlg]),
		}
	}
	if req.Payload.Csr == "" {
		return nil, &CAError{
			Code: requests.CSRMissing,
			Err:  errors.New(requests.ErrorMsg[requests.CSRMissing]),
		}
	}
	return &req, nil
}

func DecodeReNewDlgRequest(r *http.Request) (*requests.ReNewDlgRequest, *CAError) {
	// TODO more checks
	var req requests.ReNewDlgRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, &CAError{
			Code: requests.JSONDecodeError,
			Err:  err,
		}
	}
	if req.Csr == "" {
		return nil, &CAError{
			Code: requests.CSRMissing,
			Err:  errors.New(requests.ErrorMsg[requests.CSRMissing]),
		}
	}
	return &req, nil
}

func DecodeKeyChangeDlgRequest(r *http.Request) (*requests.KeyChangeDlgRequest, *CAError) {
	// TODO more checks
	var req requests.KeyChangeDlgRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, &CAError{
			Code: requests.JSONDecodeError,
			Err:  err,
		}
	}
	if req.Csr == "" {
		return nil, &CAError{
			Code: requests.CSRMissing,
			Err:  errors.New(requests.ErrorMsg[requests.CSRMissing]),
		}
	}
	return &req, nil
}

func VerifyNewDlgReqSignature(req requests.NewDlgRequest, publicKey interface{}) (bool, error) {
	headerSig, _ := json.Marshal(req.Header)
	payloadSig, _ := json.Marshal(req.Payload)
	message := append(headerSig, payloadSig...)
	sha256 := sha256.New()
	sha256.Write(message)
	digest := sha256.Sum(nil)

	byteSig := []byte{}
	byteSig, err := common.DecodeBase64(req.Signature)
	if err != nil {
		fmt.Println("error decoding b64 signature", err)
		return false, err
	}

	switch publicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA256, digest, byteSig, nil)
		if err != nil {
			logger.Warn("signature error")
			return false, err
		}
		return true, nil
	case ed25519.PublicKey:
		if !ed25519.Verify(publicKey.(ed25519.PublicKey), message, byteSig) {
			logger.Warn("signature error")
			return false, err
		}
		return true, nil
	default:
		return false, errors.New("unsupported key")
	}
}

func (myca *Ca) VerifyParentCertificate(logcerts []x509.Certificate, cert *x509.Certificate, parentzone string) ([][]*x509.Certificate, bool, error) {
	certPool := myca.CertPool

	opts := x509.VerifyOptions{
		DNSName:                   parentzone,
		Intermediates:             nil,
		Roots:                     certPool,
		CurrentTime:               time.Time{},
		KeyUsages:                 nil,
		MaxConstraintComparisions: 0,
	}
	certchains, err := cert.Verify(opts)
	if err != nil {
		fmt.Println(certchains)
		logger.Warn(fmt.Sprintln("error verifying parent cert: ", err))
		return certchains, false, err
	}
	// TODO check if cert in log !!!
	if !CheckForExistingParentCert(logcerts, *cert) {
		return nil, false, errors.New("Parent Certificate not in Log Certs list")
	}
	return certchains, true, err

}


