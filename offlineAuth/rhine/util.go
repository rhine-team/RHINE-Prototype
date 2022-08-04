package rhine

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/rhine-team/RHINE-Prototype/offlineAuth/cbor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

// Some of these functions are from the old offlineAuth implementation

func PEMBytesToHexString(pemBytes []byte) string {
	hexString := hex.EncodeToString(pemBytes)
	res := ""
	for i := 0; i < len(hexString); i += 2 {
		res = res + "\\x" + string(hexString[i]) + string(hexString[i+1])
	}
	return res
}

// Sends a cert-chain to the log-back-end (the CT personality using Trillian as storage layer)
// the first entry in the chain slice should be the end-entity certificate
func SendPreCertToLogBackend(requestURL string, chain [][]byte) (*ct.SignedCertificateTimestamp, error) {
	newReq := ct.AddChainRequest{
		Chain: chain,
	}
	serializedReq, _ := json.Marshal(newReq)
	//fmt.Printf("SendPreCertToLogBackend: serialized req: %+v", serializedReq)

	r, err := http.Post(requestURL, "application/json", bytes.NewBuffer(serializedReq))
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	defer r.Body.Close()
	body, errbody := io.ReadAll(r.Body)
	if errbody != nil {
		fmt.Println(errbody)
		return nil, errbody
	}

	//fmt.Printf("SendPreCertToLogBackend: serialized body of resp: %+v", body)

	// Unmarshal response
	resp := ct.AddChainResponse{}
	json.Unmarshal(body, &resp)

	//fmt.Printf("SendPreCertToLogBackend: unmarshaled response: %+v", resp)

	sct, errsct := resp.ToSignedCertificateTimestamp()
	if errsct != nil {
		log.Println("Error when converting: ", errsct)
	}

	return sct, nil
}

func VerifyEmbeddedSCTs(cert *x509.Certificate, issuercert *x509.Certificate, pubKey any) error {
	mLeaf, err := ct.MerkleTreeLeafForEmbeddedSCT([]*x509.Certificate{cert, issuercert}, 0)
	if err != nil {
		log.Println("Could not build ct merkle leaf out of embedded SCT")
		return err
	}

	for _, sctEmb := range cert.SCTList.SCTList {
		var sct *ct.SignedCertificateTimestamp
		sct, err = x509util.ExtractSCT(&sctEmb)
		if err != nil {
			log.Println("Failed unmarshal of SCT")
			return err
		}

		// Verify the signature
		log.Println("Verifying signature from log: ", sct.LogID)
		var verifier ct.SignatureVerifier
		verifier = ct.SignatureVerifier{PubKey: pubKey}
		mLeaf.TimestampedEntry.Timestamp = sct.Timestamp
		err = verifier.VerifySCTSignature(*sct, ct.LogEntry{Leaf: *mLeaf})
		if err != nil {
			log.Println("Failed signature Verification of an SCT: ", err)
			return err
		}
	}

	// All checks passed
	return nil
}

func EncodePublicKey(key interface{}) ([]byte, string, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		keybytes := x509.MarshalPKCS1PublicKey(key.(*rsa.PublicKey))
		return keybytes, "RSA", nil

	case *ed25519.PublicKey:
		keybytes, err := x509.MarshalPKIXPublicKey(*key.(*ed25519.PublicKey))
		if err != nil {
			return nil, "", err
		}
		return keybytes, "Ed25519", nil
	case ed25519.PublicKey:
		keybytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, "", err
		}
		return keybytes, "Ed25519", nil

	default:
		return nil, "", errors.New("unsupported key")
	}
}

func DecodePublicKey(key []byte, alg string) (interface{}, error) {
	//fmt.Println(key, alg)
	//decodedKey, err := DecodeBase64(key)
	decodedKey := key

	switch alg {
	case "RSA":
		pubKey, err := x509.ParsePKCS1PublicKey(decodedKey)
		if err != nil {
			return nil, err
		}
		return pubKey, nil

	case "Ed25519":
		pubKey, err := x509.ParsePKIXPublicKey(decodedKey)
		if err != nil {
			return nil, err
		}
		if _, ok := pubKey.(ed25519.PublicKey); ok {
			return pubKey.(ed25519.PublicKey), nil
		} else {
			return "", errors.New("public key type / alg type mismatch")
		}

	default:
		return "", errors.New("unsupported alg")
	}
}

func EncodeBase64(bytes []byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func DecodeBase64(data string) ([]byte, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(data)
	return bytes, err
}

func GetParentZone(subzone string) string {
	split := strings.SplitN(subzone, ".", 2)
	if len(split) > 1 {
		return split[1]
	} else {
		return ""
	}

}

// Keep in mind that only exported fields are serialized
func SerializeStructure[T any](data T) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func DeserializeStructure[T any](by []byte) (res T, err error) {
	buf := bytes.NewBuffer(by)
	dec := gob.NewDecoder(buf)
	dec.Decode(&res)
	return
}

// This is from offlineauth1/common
func StoreCertificateRequestPEM(path string, csr []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}

	pemcert := pem.Block{
		Type:    "CERTIFICATE REQUEST",
		Headers: nil,
		Bytes:   csr,
	}

	err = pem.Encode(file, &pemcert)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

func LoadCertificateRequestPEM(path string) ([]byte, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)

	return block.Bytes, nil
}

func StoreCertificatePEM(path string, cert []byte) error {
	file, err := os.Create(path)
	if err != nil {
		log.Println(err)
		return err
	}

	pemcert := pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   cert,
	}

	err = pem.Encode(file, &pemcert)
	if err != nil {
		log.Println(err)
		return err
	}
	file.Close()
	return nil
}

func LoadCertificatePEM(path string) (*x509.Certificate, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
func StorePrivateKeyEd25519(path string, key ed25519.PrivateKey) error {
	file, err := os.Create(path)
	if err != nil {
		log.Println(err)
	}

	privKey := pem.Block{
		Type:    "RHINE Ed25519 PRIVATE KEY",
		Headers: nil,
		Bytes:   key,
	}

	err = pem.Encode(file, &privKey)
	if err != nil {
		log.Println(err)
	}
	file.Close()
	return nil
}

func StorePublicKeyEd25519(path string, key ed25519.PublicKey) error {
	file, err := os.Create(path)
	if err != nil {
		log.Println(err)
	}

	privKey := pem.Block{
		Type:    "RHINE Ed25519 PUBLIC KEY",
		Headers: nil,
		Bytes:   key,
	}

	err = pem.Encode(file, &privKey)
	if err != nil {
		log.Println(err)
	}
	file.Close()
	return nil
}

func LoadPrivateKeyEd25519(path string) (ed25519.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)

	privKey := block.Bytes
	if err != nil {
		return nil, err
	}

	return privKey, nil

}

func StoreRSAPrivateKeyPEM(key *rsa.PrivateKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}

	privKey := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(file, &privKey)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

func StoreRSAPublicKeyPEM(key *rsa.PublicKey, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}

	pKey := pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PublicKey(key),
	}

	err = pem.Encode(file, &pKey)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

func LoadRSAPrivateKeyPEM(path string) (*rsa.PrivateKey, error) {

	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil

}

func PublicKeyToStringPEM(key interface{}) (string, error) {

	switch key.(type) {
	case *rsa.PublicKey:
		pubKey := pem.Block{
			Type:    "RSA PUBLIC KEY",
			Headers: nil,
			Bytes:   x509.MarshalPKCS1PublicKey(key.(*rsa.PublicKey)),
		}

		return string(pem.EncodeToMemory(&pubKey)), nil

	case *ed25519.PublicKey:
		bytes, err := x509.MarshalPKIXPublicKey(*key.(*ed25519.PublicKey))
		if err != nil {
			fmt.Println(err)
		}
		pubKey := pem.Block{
			Type:    "PUBLIC KEY",
			Headers: nil,
			Bytes:   bytes,
		}

		return string(pem.EncodeToMemory(&pubKey)), nil

	default:
		return "", errors.New("unsupported key")
	}

}

func PrivateKeyToStringPEM(key interface{}) (string, error) {

	switch key.(type) {
	case *rsa.PrivateKey:
		privKey := pem.Block{
			Type:    "RSA PRIVATE KEY",
			Headers: nil,
			Bytes:   x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey)),
		}

		return string(pem.EncodeToMemory(&privKey)), nil

	case *ed25519.PrivateKey:
		bytes := *key.(*ed25519.PrivateKey)

		privKey := pem.Block{
			Type:    "Ed25519 PRIVATE KEY",
			Headers: nil,
			Bytes:   []byte(bytes),
		}

		return string(pem.EncodeToMemory(&privKey)), nil

	default:
		return "", errors.New("unsupported key")
	}

}

func PrivateKeyToStringDER(key interface{}) (string, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return hex.EncodeToString(x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))), nil
	case *ed25519.PrivateKey:
		return hex.EncodeToString([]byte(*key.(*ed25519.PrivateKey))), nil
	default:
		return "", errors.New("key not supported")
	}
}

func PublicKeyFromStringPEM(key string) (interface{}, error) {

	block, _ := pem.Decode([]byte(key))

	if block.Type == "RSA PUBLIC KEY" {
		pubKey, _ := x509.ParsePKCS1PublicKey(block.Bytes)
		return pubKey, nil

	} else if block.Type == "PUBLIC KEY" {
		pubKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
		return pubKey, nil

	} else {
		return nil, errors.New("unsupported key")
	}

}

func PublicKeyFromFile(path string) (interface{}, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(bytes)

	if block.Type == "RSA PUBLIC KEY" {
		pubKey, _ := x509.ParsePKCS1PublicKey(block.Bytes)
		return pubKey, nil

	} else if block.Type == "PUBLIC KEY" {
		pubKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
		return pubKey, nil

	} else if block.Type == "RHINE Ed25519 PUBLIC KEY" {
		pubKey := block.Bytes
		return ed25519.PublicKey(pubKey), nil
	} else {
		return nil, errors.New("unsupported key")
	}
}

func CreateSelfSignedCert(pubkey interface{}, privkey interface{}, domain string) ([]byte, error) {
	if _, ok := pubkey.(*ed25519.PublicKey); ok {
		pubkey = *pubkey.(*ed25519.PublicKey)
	}
	var req x509.Certificate
	req.DNSNames = append(req.DNSNames, domain)
	req.SerialNumber = big.NewInt(1)
	req.NotBefore = time.Now()
	req.NotAfter = time.Now().Add(time.Hour)
	certbytes, err := x509.CreateCertificate(rand.Reader, &req, &req, pubkey, privkey)
	if err != nil {
		log.Println("error creating self signed cert", err)
	}

	return certbytes, err
}

func CreateSelfSignedCertCA(pubkey interface{}, privkey interface{}) ([]byte, error) {
	if _, ok := pubkey.(*ed25519.PublicKey); ok {
		pubkey = *pubkey.(*ed25519.PublicKey)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "RHINE EXAMPLE CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 356),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	certbytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pubkey, privkey)
	if err != nil {
		log.Println("error creating self signed cert", err)
	}
	return certbytes, err
}

// The point of this func is just to create a cert signed by some CA for testing purposes
func CreateCertificateUsingCA(pubkey interface{}, privkey interface{}, privKeyCA any, pathCACert string, name string) ([]byte, error) {
	if _, ok := pubkey.(*ed25519.PublicKey); ok {
		pubkey = *pubkey.(*ed25519.PublicKey)
	}
	seed := mrand.NewSource(time.Now().UnixNano())
	newr := mrand.New(seed)

	template := x509.Certificate{
		SerialNumber: big.NewInt(int64(newr.Intn(10000))),
		Subject:      pkix.Name{CommonName: "RHINE_ZONE_OWNER:" + name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 356),
		//BasicConstraintsValid: true,
		IsCA:     false,
		KeyUsage: x509.KeyUsageDigitalSignature,
		DNSNames: []string{name},
	}

	parent, errL := LoadCertificatePEM(pathCACert)
	if errL != nil {
		return nil, errL
	}

	certbytes, err := x509.CreateCertificate(rand.Reader, &template, parent, pubkey, privKeyCA)
	if err != nil {
		log.Println("Error creating testing cert signed by CA", err)
	}
	return certbytes, err
}

func EqualKeys(a any, b any) bool {
	//log.Printf("KEY ONE: %+v,  \t KEY TWO: %+v", a, b)
	switch a.(type) {
	case ed25519.PublicKey:
		bk, ok := b.(ed25519.PublicKey)
		if !ok {
			log.Println("Type mismatch, ed25519")
			return false
		}

		return bk.Equal(a.(ed25519.PublicKey))
	case *rsa.PublicKey:
		bk, ok := b.(*rsa.PublicKey)
		if !ok {
			log.Println("Type mismatch, RSA")
			return false
		}
		return bk.Equal(a.(*rsa.PublicKey))
	default:
		log.Printf("EqualKeys: False type. Type a: %T, Type b: %T", a, b)
		return false
	}
}

func GetGRPCConn(addr string) *grpc.ClientConn {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.CallContentSubtype(cbor.CBOR{}.Name())))
	if err != nil {
		log.Println("Could not connect: %v", err)
		return nil
	}
	return conn
}
