package child

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
	"github.com/rhine-team/RHINE-Prototype/common"
	"github.com/rhine-team/RHINE-Prototype/requests"
	"log"
	"net/http"
)

func CreateCSR(zone string, CA string, privKey interface{}) ([]byte, error) {
	// TODO put CA public key or ID in request
	var req x509.CertificateRequest
	req.DNSNames = append(req.DNSNames, zone)
	req.Subject.CommonName = "RHINE:" + zone
	certReqBytes, err := x509.CreateCertificateRequest(rand.Reader, &req, privKey)
	if err != nil {
		//log.Println("error creating CSR: ", err)
		return nil, err
	}
	return certReqBytes, nil
}

func ReNewDlg(Cert *x509.Certificate, privKey interface{}, CAAddress string, CheckerAddress string) ([]byte, error) {
	newReq, err := CreateReNewDlgRequest(Cert, privKey)
	if err != nil {
		return nil, err
	}
	resp, err := PostReNewDlgRequest(*newReq, CAAddress)
	if err != nil {
		return nil, err
	}
	if resp.Cert == "" {
		return nil, errors.New(resp.Error)
	}

	certbytes, _ := common.DecodeBase64(resp.Cert)

	log.Println("ReNewDlg: Cert obtained")

	checkReNewReq, err := CreateCheckReNewDlgRequest(certbytes, privKey)
	if err != nil {
		return nil, err
	}

	checkresp, err := PostCheckReNewDlgRequest(*checkReNewReq, CheckerAddress)
	if err != nil {
		return nil, err
	}
	if checkresp.Status != "OK" {
		return nil, errors.New(checkresp.Error)
	}

	log.Println("CheckReNewDlg: Cert added")

	return certbytes, nil
}

func KeyChangeDlg(Cert *x509.Certificate, privKey interface{}, newprivKey interface{}, CAAddress string, CheckerAddress string) ([]byte, error) {
	keyChangeReq, err := CreateKeyChangeDlgRequest(Cert, privKey, newprivKey)
	if err != nil {
		return nil, err
	}
	resp, err := PostKeyChangeDlgReq(*keyChangeReq, CAAddress)
	if err != nil {
		return nil, err
	}
	if resp.Cert == "" {
		return nil, errors.New(resp.Error)
	}

	certbytes, _ := common.DecodeBase64(resp.Cert)

	log.Println("KeyChangeDlg: Cert obtained")

	checkKeyChangeReq, err := CreateCheckKeyChangeDlgReq(certbytes, privKey)
	if err != nil {
		return nil, err
	}

	checkresp, err := PostCheckKeyChangeDlgRequest(*checkKeyChangeReq, CheckerAddress)
	if err != nil {
		return nil, err
	}
	if checkresp.Status != "OK" {
		return nil, errors.New(checkresp.Error)
	}

	log.Println("CheckKeyChangeDlg: Cert added")

	return certbytes, nil
}

func RevokeDlg(Cert *x509.Certificate, privKey interface{}, CheckerAddress string) error {
	revReq, err := CreateRevokeDlgRequest(Cert.Raw, privKey)
	if err != nil {
		return err
	}

	checkresp, err := PostRevokeDlgRequest(*revReq, CheckerAddress)
	if err != nil {
		return err
	}
	if checkresp.Status != "OK" {
		return errors.New(checkresp.Error)
	}

	log.Println("RevokeDlg: Certificate Revoked")

	return nil
}

func CreateRevokeDlgRequest(cert []byte, privkey interface{}) (*requests.RevokeDlgRequest, error) {
	sigbytes := []byte{}

	message := append([]byte("Revoke"), cert...)

	switch privkey.(type) {
	case ed25519.PrivateKey:
		sigbytes = ed25519.Sign(privkey.(ed25519.PrivateKey), message)
	case *rsa.PrivateKey:
		sha256 := sha256.New()
		sha256.Write(message)
		hash := sha256.Sum(nil)
		sigbytes, _ = rsa.SignPSS(rand.Reader, privkey.(*rsa.PrivateKey), crypto.SHA256, hash, nil)
	default:
		return nil, errors.New("Unsupported Privkey type")
	}

	return &requests.RevokeDlgRequest{
		Cert:      common.EncodeBase64(cert),
		Signature: common.EncodeBase64(sigbytes),
	}, nil
}

func PostRevokeDlgRequest(req requests.RevokeDlgRequest, CheckerAddress string) (*requests.CheckResponse, error) {
	jsonreq, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	address := "http://" + CheckerAddress + "/RevokeDlg"
	log.Printf("Posting Request: %#v\n", req)
	resp, err := http.Post(address, "application/json", bytes.NewReader(jsonreq))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var cResp requests.CheckResponse
	err = json.NewDecoder(resp.Body).Decode(&cResp)
	log.Printf("Response: %#v\n", cResp)

	if err != nil {
		return nil, err
	}
	return &cResp, nil
}

func CreateReNewDlgRequest(cert *x509.Certificate, privKey interface{}) (*requests.ReNewDlgRequest, error) {
	var req x509.CertificateRequest
	req.DNSNames = cert.DNSNames
	key, _ := privKey.(crypto.Signer)
	switch key.Public().(type) {
	case *rsa.PublicKey:
		pubKey, _ := key.Public().(*rsa.PublicKey)
		if !pubKey.Equal(cert.PublicKey) {
			return nil, errors.New("Key does not match key in certificate")
		}
	case ed25519.PublicKey:
		pubKey, _ := key.Public().(ed25519.PublicKey)
		if !pubKey.Equal(cert.PublicKey) {
			return nil, errors.New("Key does not match key in certificate")
		}
	}

	certReqBytes, err := x509.CreateCertificateRequest(rand.Reader, &req, privKey)
	if err != nil {
		return nil, err
	}

	return &requests.ReNewDlgRequest{
		Csr: common.EncodeBase64(certReqBytes),
	}, nil
}

func CreateKeyChangeDlgRequest(cert *x509.Certificate, privKey interface{}, newprivKey interface{}) (*requests.KeyChangeDlgRequest, error) {
	var req x509.CertificateRequest
	req.DNSNames = cert.DNSNames
	key, _ := privKey.(crypto.Signer)
	switch key.Public().(type) {
	case *rsa.PublicKey:
		pubKey, _ := key.Public().(*rsa.PublicKey)
		if !pubKey.Equal(cert.PublicKey) {
			return nil, errors.New("Old Key does not match key in certificate")
		}
	case ed25519.PublicKey:
		pubKey, _ := key.Public().(ed25519.PublicKey)
		if !pubKey.Equal(cert.PublicKey) {
			return nil, errors.New("Old Key does not match key in certificate")
		}
	}

	certReqBytes, err := x509.CreateCertificateRequest(rand.Reader, &req, newprivKey)
	if err != nil {
		return nil, err
	}

	old_key_encoded, oldKeyType, err := common.EncodePublicKey(key.Public())
	if err != nil {
		return nil, err

	}

	Signature, err := CreateKeyChangeSignature(certReqBytes, privKey)
	if err != nil {
		return nil, err
	}
	return &requests.KeyChangeDlgRequest{
		Csr:       common.EncodeBase64(certReqBytes),
		OldKeyAlg: oldKeyType,
		OldKey:    old_key_encoded,
		Signature: Signature,
	}, nil
}

func CreateKeyChangeSignature(message []byte, privKey interface{}) (string, error) {
	sigbytes := []byte{}

	switch privKey.(type) {
	case ed25519.PrivateKey:
		sigbytes = ed25519.Sign(privKey.(ed25519.PrivateKey), message)
	case *rsa.PrivateKey:
		sha256 := sha256.New()
		sha256.Write(message)
		hash := sha256.Sum(nil)
		sigbytes, _ = rsa.SignPSS(rand.Reader, privKey.(*rsa.PrivateKey), crypto.SHA256, hash, nil)
	default:
		return "", errors.New("Unsupported Privkey type")
	}

	return common.EncodeBase64(sigbytes), nil
}

func CreateCheckKeyChangeDlgReq(cert []byte, privKey interface{}) (*requests.CheckKeyChangeDlgRequest, error) {
	key, _ := privKey.(crypto.Signer)
	old_key_encoded, oldKeyType, err := common.EncodePublicKey(key.Public())
	if err != nil {
		return nil, err

	}

	Signature, err := CreateKeyChangeSignature(cert, privKey)
	if err != nil {
		return nil, err
	}
	return &requests.CheckKeyChangeDlgRequest{
		Cert:      common.EncodeBase64(cert),
		OldKeyAlg: oldKeyType,
		OldKey:    old_key_encoded,
		Signature: Signature,
	}, nil
}

func CreateCheckReNewDlgRequest(cert []byte, privkey interface{}) (*requests.CheckReNewDlgRequest, error) {
	sigbytes := []byte{}

	switch privkey.(type) {
	case ed25519.PrivateKey:
		sigbytes = ed25519.Sign(privkey.(ed25519.PrivateKey), cert)
	case *rsa.PrivateKey:
		sha256 := sha256.New()
		sha256.Write(cert)
		hash := sha256.Sum(nil)
		sigbytes, _ = rsa.SignPSS(rand.Reader, privkey.(*rsa.PrivateKey), crypto.SHA256, hash, nil)
	default:
		return nil, errors.New("Unsupported Privkey type")
	}

	return &requests.CheckReNewDlgRequest{
		Cert:      common.EncodeBase64(cert),
		Signature: common.EncodeBase64(sigbytes),
	}, nil
}
func PostReNewDlgRequest(req requests.ReNewDlgRequest, CAAddress string) (*requests.CAResponse, error) {
	jsonreq, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	address := "http://" + CAAddress + "/ReNewDlg"
	log.Printf("Posting Request: %#v\n", req)
	resp, err := http.Post(address, "application/json", bytes.NewReader(jsonreq))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var caResp requests.CAResponse
	err = json.NewDecoder(resp.Body).Decode(&caResp)
	log.Printf("Response: %#v\n", caResp)

	if err != nil {
		return nil, err
	}
	return &caResp, nil
}

func PostKeyChangeDlgReq(req requests.KeyChangeDlgRequest, CAAddress string) (*requests.CAResponse, error) {
	jsonreq, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	address := "http://" + CAAddress + "/KeyChangeDlg"
	log.Printf("Posting Request: %#v\n", req)
	resp, err := http.Post(address, "application/json", bytes.NewReader(jsonreq))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var caResp requests.CAResponse
	err = json.NewDecoder(resp.Body).Decode(&caResp)
	log.Printf("Response: %#v\n", caResp)

	if err != nil {
		return nil, err
	}
	return &caResp, nil
}

func PostCheckReNewDlgRequest(req requests.CheckReNewDlgRequest, CheckerAddress string) (*requests.CheckResponse, error) {
	jsonreq, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	address := "http://" + CheckerAddress + "/CheckReNewDlg"
	log.Printf("Posting Request: %#v\n", req)
	resp, err := http.Post(address, "application/json", bytes.NewReader(jsonreq))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var cResp requests.CheckResponse
	err = json.NewDecoder(resp.Body).Decode(&cResp)
	log.Printf("Response: %#v\n", cResp)

	if err != nil {
		return nil, err
	}
	return &cResp, nil
}

func PostCheckKeyChangeDlgRequest(req requests.CheckKeyChangeDlgRequest, CheckerAddress string) (*requests.CheckResponse, error) {
	jsonreq, err := json.Marshal(req)
	if err != nil {
		log.Fatal(err)
	}
	address := "http://" + CheckerAddress + "/CheckKeyChangeDlg"
	log.Printf("Posting Request: %#v\n", req)
	resp, err := http.Post(address, "application/json", bytes.NewReader(jsonreq))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var cResp requests.CheckResponse
	err = json.NewDecoder(resp.Body).Decode(&cResp)
	log.Printf("Response: %#v\n", cResp)

	if err != nil {
		return nil, err
	}
	return &cResp, nil
}
