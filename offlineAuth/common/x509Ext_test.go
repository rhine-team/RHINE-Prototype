package common

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestCertExtension(t *testing.T) {

	indtest := true

	pubkey, privkey, _ := ed25519.GenerateKey(rand.Reader)
	var req x509.Certificate
	req.DNSNames = append(req.DNSNames, "testcertext.rhine")
	req.SerialNumber = big.NewInt(1)
	req.NotBefore = time.Now()
	req.NotAfter = time.Now().Add(time.Hour)
	IndFlagExt, _ := CreateIndFlagExt(indtest)
	//req.Extensions = append(req.Extensions, IndFlagExt)
	req.ExtraExtensions = append(req.ExtraExtensions, IndFlagExt)
	certbytes, err := x509.CreateCertificate(rand.Reader, &req, &req, pubkey, privkey)
	if err != nil {
		fmt.Println(err)
	}

	certparsed, err := x509.ParseCertificate(certbytes)

	indreturn, err := CheckIndFlagX509Cert(*certparsed)
	if err != nil {
		fmt.Println(err)
		t.Errorf("error checking ext")
	}
	if indreturn != indtest {
		t.Errorf("check failed")
	}

}