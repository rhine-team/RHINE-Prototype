package checkerExtension

import (
	"crypto"
	"crypto/ed25519"
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
	"net/http"
	"time"
)

var logger = logger15.New("Module", "CheckerExtension")

type Checker struct {
	Address     string
	LogID       int64
	LogAddress  string
	LogPkeyPath string
	MapID       int64
	MapAddress  string
	MapPkeyPath string
	CertPool    *x509.CertPool
}

type CheckerError struct {
	Code int
	Err  error
}

func (e *CheckerError) Error() string {
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

func NewChecker(config Config) *Checker {
	CheckerCertPool, err := x509.SystemCertPool()
	if err == nil {
		CheckerCertPool = x509.NewCertPool()
	}

	checker := Checker{
		LogID:       config.LogID,
		LogAddress:  config.LogAddress,
		LogPkeyPath: config.LogPkeyPath,
		MapID:       config.MapID,
		MapAddress:  config.MapAddress,
		MapPkeyPath: config.MapPkeyPath,
		CertPool:    CheckerCertPool,
		Address:     config.ServerAddress,
	}

	files, err := ioutil.ReadDir(config.RootCertsPath)
	if err != nil {
		log.Fatal("Error reading roots directory: ", err)
	}

	for _, file := range files {
		pemfile, _ := ioutil.ReadFile(config.RootCertsPath + file.Name())
		if checker.CertPool.AppendCertsFromPEM(pemfile) {
			logger.Warn("Added " + file.Name() + " to trust root")
		}
	}

	return &checker
}

func DecodeCheckNewDlgRequest(r *http.Request) (*requests.CheckNewDlgRequest, *CheckerError) {
	logger.Info("Checker: Decoding CheckNewDlg Request")
	//TODO more checks
	var req requests.CheckNewDlgRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.JSONDecodeError,
			Err:  err,
		}
	}
	return &req, nil
}

func DecodeCheckReNewDlgRequest(r *http.Request) (*requests.CheckReNewDlgRequest, *CheckerError) {
	logger.Info("Checker: Decoding CheckReNewDlg Request")
	//TODO more checks
	var req requests.CheckReNewDlgRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.JSONDecodeError,
			Err:  err,
		}
	}
	return &req, nil
}

func DecodeCheckKeyChangeDlgRequest(r *http.Request) (*requests.CheckKeyChangeDlgRequest, *CheckerError) {
	logger.Info("Checker: Decoding CheckReNewDlg Request")
	//TODO more checks
	var req requests.CheckKeyChangeDlgRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.JSONDecodeError,
			Err:  err,
		}
	}
	return &req, nil
}

func DecodeRevokeDlgRequest(r *http.Request) (*requests.RevokeDlgRequest, *CheckerError) {
	logger.Info("Checker: Decoding RevokeDlg Request")
	//TODO more checks
	var req requests.RevokeDlgRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.JSONDecodeError,
			Err:  err,
		}
	}
	return &req, nil
}

func (c *Checker) ProcessCheckNewDlgRequest(preq requests.CheckNewDlgRequest) (*x509.Certificate, *CheckerError) {
	logger.Info("Checker: Processing CheckNewDlg Request")

	// parse child cert
	childCertBytes, err := common.DecodeBase64(preq.Payload.Cert)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.CertDecodeError,
			Err:  err,
		}
	}
	childCert, err := x509.ParseCertificate(childCertBytes)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.CertParseError,
			Err:  err,
		}
	}

	// read parent zone
	childzone := childCert.DNSNames[0]
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
		logger.Info("Checker: Authenticating Parent: DNSSEC")
		var err error
		switch preq.Header.Alg {
		case "RSA":
			publicKey, err = common.QueryDNSKeyRSA(parentzone)
		case "Ed25519":
			publicKey, err = common.QueryDNSKeyEd25519(parentzone)
		}

		if err != nil {
			return nil, &CheckerError{
				Code: requests.ParentAuthDNSSECFailed,
				Err:  err,
			}
		}
		logger.Info("Checker: Authenticated Parent DNSSEC")

	case "certificate":
		logger.Info("Checker: Authenticating Parent: Certificate")
		certbytes, err := common.DecodeBase64(preq.Header.Parent_cert)
		if err != nil {
			return nil, &CheckerError{
				Code: requests.ParentAuthCertDecodeError,
				Err:  err,
			}
		}
		parentcert, err := x509.ParseCertificate(certbytes)
		if err != nil {
			return nil, &CheckerError{
				Code: requests.ParentAuthCertParseError,
				Err:  err,
			}
		}
		if parentcert != nil {
			publicKey = parentcert.PublicKey
		} else {
			return nil, &CheckerError{
				Code: requests.ParentAuthCertParseError,
				Err:  errors.New("Public Key in Certificate missing"),
			}
		}

		parentlogcerts, err := rainsclientlog.QueryMapServerZoneInfo(parentzone, c.MapID, c.MapAddress, c.MapPkeyPath)
		if err != nil {
			return nil, &CheckerError{
				Code: requests.MapServerConnectionFailed,
				Err:  err,
			}
		}
		validParentCerts := c.FilterValidCertsFromChains(parentlogcerts, parentzone)

		if _, ok, err := c.VerifyParentCertificate(validParentCerts, parentcert, parentzone); !ok {
			return nil, &CheckerError{
				Code: requests.ParentAuthCertInvalid,
				Err:  err,
			}
		}
		logger.Info("Checker: Parent Certificate Verified")
	default:
		return nil, &CheckerError{
			Code: requests.AuthTypeMissing,
			Err:  errors.New(requests.ErrorMsg[requests.AuthTypeMissing]),
		}
	}

	//verify parent sig
	if ok, err := VerifyCheckNewDlgReqSignature(preq, publicKey); ok {
	} else {
		return nil, &CheckerError{
			Code: requests.InvalidSignature,
			Err:  err,
		}
	}
	logger.Info("Checker: Parent Signature Verified")

	// verify child cert
	if _, ok, err := c.VerifyChildCertificate(childCert); !ok {
		return nil, &CheckerError{
			Code: requests.CertInvalid,
			Err:  err,
		}
	}
	logger.Info("Checker: Child Certificate Verified")

	return childCert, nil
}

func (c *Checker) ProcessCheckReNewDlgRequest(req requests.CheckReNewDlgRequest) (*x509.Certificate, *CheckerError) {
	logger.Info("Checker: Processing CheckReNewDlg Request")

	// parse child cert
	childCertBytes, err := common.DecodeBase64(req.Cert)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.CertDecodeError,
			Err:  err,
		}
	}
	childCert, err := x509.ParseCertificate(childCertBytes)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.CertParseError,
			Err:  err,
		}
	}

	childzone := childCert.DNSNames[0]
	var publicKey interface{}
	publicKey = childCert.PublicKey

	if ok, err := VerifyCheckReNewDlgReqSignature(req, publicKey); ok {
	} else {
		return nil, &CheckerError{
			Code: requests.InvalidSignature,
			Err:  err,
		}
	}

	logger.Info("Checker: ReNewDlg Signature Verified")

	// verify child cert
	if _, ok, err := c.VerifyChildCertificate(childCert); !ok {
		return nil, &CheckerError{
			Code: requests.CertInvalid,
			Err:  err,
		}
	}

	logger.Info("Checker: ReNewDlg Child Cert Verified")

	logcerts, err := rainsclientlog.QueryMapServerZoneInfo(childzone, c.MapID, c.MapAddress, c.MapPkeyPath)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.MapServerConnectionFailed,
			Err:  err,
		}
	}

	logger.Info("Checker: ReNewDlg:  Map Queried")

	validCerts := c.FilterValidCertsFromChains(logcerts, childzone)

	if ok := CheckForExistingCert(validCerts, *childCert); !ok {
		return nil, &CheckerError{
			Code: requests.RequiredCertNotInLog,
			Err:  errors.New(requests.ErrorMsg[requests.RequiredCertNotInLog]),
		}
	}

	logger.Info("Checker: ReNewDlg: Existing Cert in Log found, New Certificate Approved")

	logger.Info("Checker: Request OK")
	return childCert, nil

}

func (c *Checker) ProcessCheckKeyChangeDlgRequest(req requests.CheckKeyChangeDlgRequest) (*x509.Certificate, *CheckerError) {
	logger.Info("Checker: Processing CheckKeyChangeDlg Request")

	// parse child cert
	childCertBytes, err := common.DecodeBase64(req.Cert)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.CertDecodeError,
			Err:  err,
		}
	}
	childCert, err := x509.ParseCertificate(childCertBytes)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.CertParseError,
			Err:  err,
		}
	}

	childzone := childCert.DNSNames[0]

	var oldPublicKey interface{}
	oldPublicKey, err = common.DecodePublicKey(req.OldKey, req.OldKeyAlg)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.OldKeyDecodeError,
			Err:  err,
		}
	}

	if ok, err := VerifyKeyChangeSignature(req, oldPublicKey); ok {
	} else {
		return nil, &CheckerError{
			Code: requests.InvalidSignature,
			Err:  err,
		}
	}
	logger.Info("Checker: KeyChangeDlg Signature Verified")

	// verify child cert
	if _, ok, err := c.VerifyChildCertificate(childCert); !ok {
		return nil, &CheckerError{
			Code: requests.CertInvalid,
			Err:  err,
		}
	}
	logger.Info("Checker: ReNewDlg Child Cert Verified")

	logcerts, err := rainsclientlog.QueryMapServerZoneInfo(childzone, c.MapID, c.MapAddress, c.MapPkeyPath)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.MapServerConnectionFailed,
			Err:  err,
		}
	}
	logger.Info("Checker: ReNewDlg:  Map Queried")

	validCerts := c.FilterValidCertsFromChains(logcerts, childzone)

	if ok := CheckForExistingCertKeyChange(validCerts, *childCert, oldPublicKey); !ok {
		return nil, &CheckerError{
			Code: requests.RequiredCertNotInLog,
			Err:  errors.New(requests.ErrorMsg[requests.RequiredCertNotInLog]),
		}
	}

	logger.Info("Checker: ReNewDlg: Existing Cert in Log found, New Certificate Approved")

	logger.Info("Checker: Request OK")
	return childCert, nil

}

func (c *Checker) ProcessRevokeDlgRequest(req requests.RevokeDlgRequest) (*x509.Certificate, *CheckerError) {
	logger.Info("Checker: Processing RevokeDlg Request")

	// parse child cert
	childCertBytes, err := common.DecodeBase64(req.Cert)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.CertDecodeError,
			Err:  err,
		}
	}
	childCert, err := x509.ParseCertificate(childCertBytes)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.CertParseError,
			Err:  err,
		}
	}

	childzone := childCert.DNSNames[0]
	var publicKey interface{}
	publicKey = childCert.PublicKey

	if ok, err := VerifyRevokeDlgReqSignature(req, publicKey); ok {
	} else {
		return nil, &CheckerError{
			Code: requests.InvalidSignature,
			Err:  err,
		}
	}

	logger.Info("Checker: ReNewDlg Signature Verified")

	// verify child cert
	if _, ok, err := c.VerifyChildCertificate(childCert); !ok {
		return nil, &CheckerError{
			Code: requests.CertInvalid,
			Err:  err,
		}
	}

	logger.Info("Checker: ReNewDlg Child Cert Verified")

	logcerts, err := rainsclientlog.QueryMapServerZoneInfo(childzone, c.MapID, c.MapAddress, c.MapPkeyPath)
	if err != nil {
		return nil, &CheckerError{
			Code: requests.MapServerConnectionFailed,
			Err:  err,
		}
	}

	logger.Info("Checker: ReNewDlg:  Map Queried")

	validCerts := c.FilterValidCertsFromChains(logcerts, childzone)

	if ok := FindCert(validCerts, *childCert); !ok {
		return nil, &CheckerError{
			Code: requests.RequiredCertNotInLog,
			Err:  errors.New(requests.ErrorMsg[requests.RequiredCertNotInLog]),
		}
	}

	logger.Info("Checker: Request OK")
	return childCert, nil

}

func VerifyKeyChangeSignature(req requests.CheckKeyChangeDlgRequest, publicKey interface{}) (bool, error) {
	message, err := common.DecodeBase64(req.Cert)
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

func CheckForExistingCert(certs []x509.Certificate, reqCert x509.Certificate) bool {
	for _, cert := range certs {
		switch reqCert.PublicKey.(type) {
		case *rsa.PublicKey:
			csrKey, _ := reqCert.PublicKey.(*rsa.PublicKey)
			if !csrKey.Equal(cert.PublicKey) {
				continue
			}
		case ed25519.PublicKey:
			csrKey, _ := reqCert.PublicKey.(ed25519.PublicKey)
			if !csrKey.Equal(cert.PublicKey) {
				continue
			}
		default:
			continue
		}
		for i, name := range reqCert.DNSNames {
			if !(name == cert.DNSNames[i]) {
				continue
			}
		}
		return true
	}
	return false
}

func FindCert(certs []x509.Certificate, reqCert x509.Certificate) bool {
	for _, cert := range certs {
		if cert.Equal(&reqCert) {
			logger.Info("Cert to Revoke found in Log (valid)")
			return true
		}

	}
	return false
}

func CheckForExistingCertKeyChange(certs []x509.Certificate, reqCert x509.Certificate, pubKey interface{}) bool {
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
		for i, name := range reqCert.DNSNames {
			if !(name == cert.DNSNames[i]) {
				continue
			}
		}
		return true
	}
	return false
}

func (c *Checker) FilterValidCertsFromChains(certchains [][]x509.Certificate, zone string) []x509.Certificate {
	var validCerts []x509.Certificate
	for _, certchain := range certchains {
		cert := certchain[0]
		if _, err := cert.Verify(x509.VerifyOptions{
			DNSName:                   zone,
			Intermediates:             nil,
			Roots:                     c.CertPool,
			CurrentTime:               time.Time{},
			KeyUsages:                 nil,
			MaxConstraintComparisions: 0,
		}); err == nil {
			validCerts = append(validCerts, cert)
		}
	}
	return validCerts
}

func VerifyCheckReNewDlgReqSignature(req requests.CheckReNewDlgRequest, publicKey interface{}) (bool, error) {
	message, _ := common.DecodeBase64(req.Cert)
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

func VerifyRevokeDlgReqSignature(req requests.RevokeDlgRequest, publicKey interface{}) (bool, error) {
	certbytes, _ := common.DecodeBase64(req.Cert)
	message := append([]byte("Revoke"), certbytes...)
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

func VerifyCheckNewDlgReqSignature(req requests.CheckNewDlgRequest, publicKey interface{}) (bool, error) {
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

func (c *Checker) VerifyChildCertificate(cert *x509.Certificate, ) ([][]*x509.Certificate, bool, error) {
	certPool := c.CertPool

	opts := x509.VerifyOptions{
		Roots:                     certPool,
		CurrentTime:               time.Time{},
		KeyUsages:                 nil,
		MaxConstraintComparisions: 0,
	}
	certchains, err := cert.Verify(opts)
	if err != nil {
		fmt.Println(certchains)
		logger.Warn(fmt.Sprintln("error verifying child cert: ", err))
		return certchains, false, err
	}
	return certchains, true, err

}

func (c *Checker) VerifyParentCertificate(logcerts []x509.Certificate, cert *x509.Certificate, parentzone string) ([][]*x509.Certificate, bool, error) {
	certPool := c.CertPool

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


