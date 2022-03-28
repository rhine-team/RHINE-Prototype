// A Proof stores a set of map entries and corresponding inclusion proofs for the effective second level domain and all subdomains and a signed map root to verify the validity of the inclusion proofs

package tclient

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/x509"
	"github.com/google/trillian"
	"io"
	"log"
	"math/big"
	"testing"
)

func TestProofTypeMarshalCompressed(t *testing.T) {
	in := testCreateProof()
	in.SetEnableCompression(true)
	// log.Printf("in = %+v", in)
	inEncoded, err := in.MarshalBinary()
	if err != nil {
		t.Errorf("Couldn't marshal proofType: %s", err)
	}
	var out proofType
	out.SetEnableCompression(true)
	err = out.UnmarshalBinary(inEncoded)
	if err != nil {
		t.Errorf("Couldn't unmarshal proofType: %s", err)
	}
	if !testProofTypeIsEqual(in, out) {
		t.Errorf("proofType changed after marshal/unmarshal: %+v != %+v: %s", in.ToString(), out.ToString(), err)
	}
}

func TestProofTypeMarshal(t *testing.T) {
	in := testCreateProof()
	// log.Printf("in = %+v", in)
	inEncoded, err := in.MarshalBinary()
	if err != nil {
		t.Errorf("Couldn't marshal proofType: %s", err)
	}
	var out proofType
	err = out.UnmarshalBinary(inEncoded)
	if err != nil {
		t.Errorf("Couldn't unmarshal proofType: %s", err)
	}
	if !testProofTypeIsEqual(in, out) {
		t.Errorf("proofType changed after marshal/unmarshal: %+v != %+v: %s", in.ToString(), out.ToString(), err)
	}
}

func testCreateProof() proofType {
	var s1, s2, s3 big.Int
	s1.SetUint64(1234)
	s2.SetUint64(4321)
	s3.SetUint64(6789)
	var e1, e2 proofMapEntryType
	e1.Certificates = [][]x509.Certificate{[]x509.Certificate{*testCreateCertificate(), *testCreateCertificate()}, []x509.Certificate{*testCreateCertificate(), *testCreateCertificate()}}
	e1.Revocations = []RevocationMessageType{RevocationMessageType{SerialNumber: s1, Message: []byte{1, 2, 3, 4, 5, 6, 7, 8}}}
	e1.WildcardCertificates = [][]x509.Certificate{}
	e1.WildcardRevocations = []RevocationMessageType{}
	e1.SubtreeRoot = []byte{3, 3, 3, 3, 3, 3, 3, 3}
	e1.mapID = 3
	e2.Certificates = [][]x509.Certificate{[]x509.Certificate{*testCreateCertificate(), *testCreateCertificate(), *testCreateCertificate()}, []x509.Certificate{*testCreateCertificate(), *testCreateCertificate(), *testCreateCertificate()}, []x509.Certificate{*testCreateCertificate(), *testCreateCertificate(), *testCreateCertificate()}}
	e2.Revocations = []RevocationMessageType{RevocationMessageType{SerialNumber: s2, Message: []byte{1, 2, 3, 4, 5, 6, 7, 8}}}
	e2.WildcardCertificates = [][]x509.Certificate{}
	e2.WildcardRevocations = []RevocationMessageType{RevocationMessageType{SerialNumber: s3, Message: []byte{6, 6, 6, 6, 6, 6, 6}}}
	e2.SubtreeRoot = []byte{7, 7, 7, 7, 7, 7, 7, 7}
	e2.mapID = 7

	var p proofType
	p.mapEntries = append(p.mapEntries, e1)
	p.mapEntries = append(p.mapEntries, e2)
	p.inclusionProofs = append(p.inclusionProofs, InclusionProofType{[]byte{1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}, []byte{}, []byte{}, []byte{5, 6, 7, 8, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}})
	p.inclusionProofs = append(p.inclusionProofs, InclusionProofType{[]byte{11, 22, 33, 44, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}, []byte{}, []byte{}, []byte{55, 66, 77, 88, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4, 1, 2, 3, 4}})
	var smr trillian.SignedMapRoot
	smr.MapRoot = []byte{1, 2, 3, 4, 5, 6, 7}
	smr.Signature = []byte{9, 9, 9, 9, 9}
	p.signedMapRoot = smr
	p.SetDomain("a.b.com")
	return p
}

func testProofTypeIsEqual(a, b proofType) bool {
	if len(a.mapEntries) != len(b.mapEntries) {
		return false
	}
	if len(a.inclusionProofs) != len(b.inclusionProofs) {
		return false
	}
	for i, ai := range a.mapEntries {
		if !testProofMapEntryTypeIsEqual(ai, b.mapEntries[i]) {
			return false
		}
	}
	for i, ai := range a.inclusionProofs {
		bi := b.inclusionProofs[i]
		if len(ai) != len(bi) {
			return false
		}
		for j, aij := range ai {
			if bytes.Compare(aij, bi[j]) != 0 {
				return false
			}
		}
	}
	if bytes.Compare(a.signedMapRoot.MapRoot, b.signedMapRoot.MapRoot) != 0 {
		return false
	}
	if bytes.Compare(a.signedMapRoot.Signature, b.signedMapRoot.Signature) != 0 {
		return false
	}
	return true
}

func testProofMapEntryTypeIsEqual(a, b proofMapEntryType) bool {
	if len(a.Certificates) != len(b.Certificates) {
		return false
	}
	if len(a.WildcardCertificates) != len(b.WildcardCertificates) {
		return false
	}
	if len(a.Revocations) != len(b.Revocations) {
		return false
	}
	if len(a.WildcardRevocations) != len(b.WildcardRevocations) {
		return false
	}
	if len(a.SubtreeRoot) != len(b.SubtreeRoot) {
		return false
	}

	for i, _ := range a.Certificates {
		if len(a.Certificates[i]) != len(b.Certificates[i]) {
			return false
		}
		for j, _ := range a.Certificates[i] {
			if (a.Certificates[i][j].SerialNumber).Cmp(b.Certificates[i][j].SerialNumber) != 0 {
				return false
			}
		}
	}
	for i, _ := range a.WildcardCertificates {
		if len(a.WildcardCertificates[i]) != len(b.WildcardCertificates[i]) {
			return false
		}
		for j, _ := range a.WildcardCertificates[i] {
			if (a.WildcardCertificates[i][j].SerialNumber).Cmp(b.WildcardCertificates[i][j].SerialNumber) != 0 {
				return false
			}
		}
	}
	for i, ai := range a.Revocations {
		if (&ai.SerialNumber).Cmp(&b.Revocations[i].SerialNumber) != 0 {
			return false
		}
	}
	for i, ai := range a.WildcardRevocations {
		if (&ai.SerialNumber).Cmp(&b.WildcardRevocations[i].SerialNumber) != 0 {
			return false
		}
	}
	if !bytes.Equal(a.SubtreeRoot, b.SubtreeRoot) {
		return false
	}
	return true
}
