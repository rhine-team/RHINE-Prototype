// A MapEntry stores certificates valid for a specific (wildcard-)domain and possibly the root of a tree for subdomains

package tclient

import (
	"bytes"
	"crypto/x509"
	"encoding"
	"encoding/asn1"
	"fmt"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/common"
	"math/big"
)

type RevocationMessage interface {
	// Returns nil if the revocation message (the embedded signature) is valid
	Validate() error

	GetMessage() []byte
	GetRevokedSerialNumber() big.Int
}

type MapEntry interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	ToString() string

	GetCertificates() [][]x509.Certificate
	GetRevocations() []RevocationMessage
	GetWildcardCertificates() [][]x509.Certificate
	GetWildcardRevocations() []RevocationMessage
	GetSubtreeRoot() []byte
}

type RevocationMessageType struct {
	SerialNumber big.Int
	Message      []byte
}

type revocationMessageDataType struct {
	SerialNumber []byte
	Message      []byte
}

type MapEntryType struct {
	// domain under which the map entry is stored in the map (is not encoded into the binary representation)
	domain string
	// the first certificate in the chain is the endpoint certificate and the last certificate is the certificate issued by a root certificate
	Certificates         [][]x509.Certificate
	Revocations          []RevocationMessageType
	WildcardCertificates [][]x509.Certificate
	WildcardRevocations  []RevocationMessageType
	SubtreeRoot          []byte
}

type mapEntryDataType struct {
	Certificates         [][]byte
	Revocations          [][]byte
	WildcardCertificates [][]byte
	WildcardRevocations  [][]byte
	SubtreeRoot          []byte
}

func (me *RevocationMessageType) GetMessage() []byte {
	return me.Message
}

func (me *RevocationMessageType) GetRevokedSerialNumber() big.Int {
	return me.SerialNumber
}

func (me *RevocationMessageType) Validate() error {
	//TODO(cyrill) implement signature checking + signature algorithm
	return nil
}

func (me *MapEntryType) Merge(other *MapEntryType) {
	mergeCertificates(&me.Certificates, other.Certificates)
	mergeRevocationMessages(&me.Revocations, other.Revocations)
	mergeCertificates(&me.WildcardCertificates, other.WildcardCertificates)
	mergeRevocationMessages(&me.WildcardRevocations, other.WildcardRevocations)
}

func mergeCertificates(l1 *[][]x509.Certificate, l2 [][]x509.Certificate) {
	for _, e2 := range l2 {
		// common.Debug("Checking if %d: %s already exists ...", j, common.X509CertChainToString(e2))
		add := true
		for _, e1 := range *l1 {
			if len(e1) == len(e2) {
				i := 0
				for ; i < len(e1); i++ {
					if !bytes.Equal(e1[i].Raw, e2[i].Raw) {
						// common.Debug("Found different cert in chain at %d: %s", i, common.X509CertToString(&e2[i]))
						break
					}
				}
				if i == len(e1) {
					// common.Debug("Not adding %s", common.X509CertChainToString(e2))
					add = false
					break
				}
			}
		}
		if add {
			// common.Debug("Adding %s", common.X509CertChainToString(e2))
			*l1 = append(*l1, e2)
		}
	}
}

func mergeRevocationMessages(l1 *[]RevocationMessageType, l2 []RevocationMessageType) {
	for _, e2 := range l2 {
		add := true
		for _, e1 := range *l1 {
			if bytes.Equal(e1.Message, e2.Message) && (&e1.SerialNumber).Cmp(&e2.SerialNumber) == 0 {
				add = false
				break
			}
		}
		if add {
			*l1 = append(*l1, e2)
		}
	}
}

func (me *MapEntryType) MarshalBinary() (data []byte, err error) {
	var d mapEntryDataType
	for _, c := range me.Certificates {
		var chain []byte
		for _, x := range c {
			chain = append(chain, x.Raw...)
		}
		d.Certificates = append(d.Certificates, chain)
	}

	for _, r := range me.Revocations {
		rmd := revocationMessageDataType{SerialNumber: r.SerialNumber.Bytes(), Message: r.Message}
		revocationBytes, err := asn1.Marshal(rmd)
		if err != nil {
			return nil, fmt.Errorf("Couldn't marshal revocation: %s", err)
		}
		d.Revocations = append(d.Revocations, revocationBytes)
	}

	for _, c := range me.WildcardCertificates {
		var chain []byte
		for _, x := range c {
			chain = append(chain, x.Raw...)
		}
		d.WildcardCertificates = append(d.WildcardCertificates, chain)
	}

	for _, r := range me.WildcardRevocations {
		rmd := revocationMessageDataType{SerialNumber: r.SerialNumber.Bytes(), Message: r.Message}
		revocationBytes, err := asn1.Marshal(rmd)
		if err != nil {
			return nil, fmt.Errorf("Couldn't marshal wildcard revocation: %s", err)
		}
		d.WildcardRevocations = append(d.WildcardRevocations, revocationBytes)
	}

	//copy(d.SubtreeRoot, me.SubtreeRoot)
	d.SubtreeRoot = me.SubtreeRoot

	return asn1.Marshal(d)
}

func (me *MapEntryType) UnmarshalBinary(data []byte) error {
	me.Certificates = nil
	me.WildcardCertificates = nil
	me.Revocations = nil
	me.WildcardRevocations = nil

	var d mapEntryDataType
	_, err := asn1.Unmarshal(data, &d)
	if err != nil {
		return fmt.Errorf("Couldn't unmarshal mapEntryDataType: %s", err)
	}

	for _, cBytes := range d.Certificates {
		c, err := x509.ParseCertificates(cBytes)
		if err != nil {
			return fmt.Errorf("Couldn't parse x509 certificate: %s", err)
		}
		var chain []x509.Certificate
		for _, x := range c {
			chain = append(chain, *x)
		}
		me.Certificates = append(me.Certificates, chain)
	}

	for _, cBytes := range d.WildcardCertificates {
		c, err := x509.ParseCertificates(cBytes)
		if err != nil {
			return fmt.Errorf("Couldn't parse x509 certificate: %s", err)
		}
		var chain []x509.Certificate
		for _, x := range c {
			chain = append(chain, *x)
		}
		me.WildcardCertificates = append(me.WildcardCertificates, chain)
	}

	for _, rBytes := range d.Revocations {
		var rmd revocationMessageDataType
		_, err := asn1.Unmarshal(rBytes, &rmd)
		var s big.Int
		s.SetBytes(rmd.SerialNumber)
		r := RevocationMessageType{SerialNumber: s, Message: rmd.Message}
		if err != nil {
			return fmt.Errorf("Couldn't parse revocation message: %s", err)
		}
		me.Revocations = append(me.Revocations, r)
	}

	for _, rBytes := range d.WildcardRevocations {
		var rmd revocationMessageDataType
		_, err := asn1.Unmarshal(rBytes, &rmd)
		var s big.Int
		s.SetBytes(rmd.SerialNumber)
		r := RevocationMessageType{SerialNumber: s, Message: rmd.Message}
		if err != nil {
			return fmt.Errorf("Couldn't parse revocation message: %s", err)
		}
		me.WildcardRevocations = append(me.WildcardRevocations, r)
	}

	//copy(me.SubtreeRoot, d.SubtreeRoot)
	me.SubtreeRoot = d.SubtreeRoot

	return nil
}

type certLogFunction func(*[]x509.Certificate) string
type revocationLogFunction func(*RevocationMessageType) string

func (me *MapEntryType) toString(cLog certLogFunction, rLog revocationLogFunction) string {
	output := "<MapEntryType "
	if me.domain != "" {
		output += me.domain + " "
	}
	isFirst := true
	if len(me.Certificates) != 0 {
		if !isFirst {
			output += ", "
		}
		isFirst = false
		output += "certs='"
		for i, c := range me.Certificates {
			if i != 0 {
				output += ", "
			}
			output += cLog(&c)
		}
		output += "'"
	}

	if len(me.Revocations) != 0 {
		if !isFirst {
			output += ", "
		}
		isFirst = false
		output += "revocations='"
		for i, c := range me.Revocations {
			if i != 0 {
				output += ", "
			}
			output += rLog(&c)
		}
		output += "'"
	}

	if len(me.WildcardCertificates) != 0 {
		if !isFirst {
			output += ", "
		}
		isFirst = false
		output += "wildcard certs='"
		for i, c := range me.WildcardCertificates {
			if i != 0 {
				output += ", "
			}
			output += cLog(&c)
		}
		output += "'"
	}

	if len(me.WildcardRevocations) != 0 {
		if !isFirst {
			output += ", "
		}
		isFirst = false
		output += "wildcard revocations='"
		for i, c := range me.WildcardRevocations {
			if i != 0 {
				output += ", "
			}
			output += rLog(&c)
		}
		output += "'"
	}

	if len(me.SubtreeRoot) != 0 {
		if !isFirst {
			output += ", "
		}
		isFirst = false
		output += fmt.Sprintf("subtreeRoot='%x'", me.SubtreeRoot)
	}
	return output + ">"
}

func (me *MapEntryType) ToString() string {
	return me.toString(
		func(c *[]x509.Certificate) string { return common.X509CertChainToString(*c) },
		func(r *RevocationMessageType) string { return r.SerialNumber.Text(10) })
}

func (me *MapEntryType) SetDomain(domain string) {
	me.domain = domain
}

func (me *MapEntryType) GetCertificates() [][]x509.Certificate {
	return me.Certificates
}

func (me *MapEntryType) GetRevocations() []RevocationMessage {
	var out []RevocationMessage
	for _, m := range me.Revocations {
		out = append(out, &m)
	}
	return out
}

func (me *MapEntryType) GetWildcardCertificates() [][]x509.Certificate {
	return me.WildcardCertificates
}

func (me *MapEntryType) GetWildcardRevocations() []RevocationMessage {
	var out []RevocationMessage
	for _, m := range me.WildcardRevocations {
		out = append(out, &m)
	}
	return out
}

func (me *MapEntryType) GetSubtreeRoot() []byte {
	return me.SubtreeRoot
}
