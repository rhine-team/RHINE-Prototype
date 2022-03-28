package common

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

var (
	RhineIndFlagExtOID = asn1.ObjectIdentifier{1, 3, 500, 9}
)

type IndFlagExt struct {
	Independent bool
}

func CheckIndFlagX509Cert(cert x509.Certificate) (bool, error) {
	exts := cert.Extensions
	FlagExt, err := ParseIndFlagExt(exts)
	if err != nil {
		return false, err
	}

	return FlagExt.Independent, nil
}

func ParseIndFlagExt (exts []pkix.Extension) (IndFlagExt, error) {
	if len(exts) == 0 {
		return IndFlagExt{}, errors.New("No RhineIndFlagExt to parse")
	}

	var rhineext *pkix.Extension

	for _, ext := range exts{
		if ext.Id.Equal(RhineIndFlagExtOID){
			rhineext = &ext
		}
	}

	if rhineext == nil {
		return IndFlagExt{}, errors.New("ext OID is not RhineIndFlagExt")
	}
	var FlagExt IndFlagExt
	_ , err := asn1.Unmarshal(rhineext.Value, &FlagExt)
	if err != nil {
		return IndFlagExt{}, err
	}
	return FlagExt, nil
}

func CreateIndFlagExt (value bool) (pkix.Extension, error) {
	data, err := asn1.Marshal(IndFlagExt{Independent: value})
	if err != nil {
		return pkix.Extension{}, err
	}
	ext := pkix.Extension{
		Id:       RhineIndFlagExtOID,
		Critical: false,
		Value:    data,
	}

	return ext, nil
}

func FilterIndependentZoneCerts(certs []x509.Certificate) ([]x509.Certificate) {
	var indCerts []x509.Certificate
	for _ , cert := range certs {
		isIndependent, err := CheckIndFlagX509Cert(cert)
		if err != nil {
			continue
		}
		if !isIndependent {
			continue
		}
		indCerts = append(indCerts, cert)

	}
	return indCerts
}


