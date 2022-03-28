// A ProofEntry stores map entries and inclusion proofs necessary to validate the proof chain

package tclient

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/x509"
	"encoding"
	"encoding/asn1"
	"fmt"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/common"
	"github.com/google/trillian"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/maphasher"
	"io"
	"log"
	"strings"
)

type InclusionProofType [][]byte

type Proof interface {
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
	// returns true if the inclusion proof at the last level (excluding wildcard level) is a non-empty leaf
	IsProofOfPresence() bool
	SetEnableCompression(enable bool)

	// Set the domain for which this proof is valid; if split using common.SplitE2LD(), must return len(mapEntries) labels (only used for debugging purposes, domain provided in Validate() is used for validation)
	SetDomain(domain string) error
	// Get the full domain name (only used for debugging purposes, domain provided in Validate() is used for validation)
	GetDomain() string

	// Returns in how many inclusion proofs is the proof split into (excluding wildcard level)
	GetNumberOfEntries() int
	// Return the entry at a specific level, where 0 is the effective second-level domain
	GetEntry(level int) MapEntry
	// Verify the validity of the proof
	Validate(mapID int64, mapPK crypto.PublicKey, treeNonce []byte, domain string) error
	GetUnrevokedCertificatesSignedByCAs(domain string, caAuthorityKeyIdentifiers [][]byte) [][]x509.Certificate
	GetUnrevokedCertificates(domain string) [][]x509.Certificate
	GetAllCertificates() [][]x509.Certificate
	ToString() string
	GetInclusionProofSize() (int, error)
}

func NewProof() Proof {
	return &proofType{}
}

type proofMapEntryType struct {
	MapEntryType
	mapID int64
}

type proofType struct {
	enableCompression bool
	mapEntries        []proofMapEntryType
	// contains a slice of hashes for each entry with the corresponding hashes
	inclusionProofs []InclusionProofType
	signedMapRoot   trillian.SignedMapRoot
}

type proofDataType struct {
	MapEntries      [][]byte
	InclusionProofs [][]byte
	SignedMapRoot   []byte
}

func (p *proofType) SetEnableCompression(enable bool) {
	p.enableCompression = enable
}

func (p *proofType) GetInclusionProofSize() (int, error) {
	var inclusionProofs [][]byte
	for _, ip := range p.inclusionProofs {
		data, err := ip.MarshalBinary()
		if err != nil {
			return 0, err
		}
		inclusionProofs = append(inclusionProofs, data)
	}
	d, err := asn1.Marshal(inclusionProofs)
	if err != nil {
		return 0, err
	}
	return len(d), nil
}

func (p *proofType) GetUnrevokedCertificates(domain string) [][]x509.Certificate {
	return p.getUnrevokedCertificates(domain, func(c []x509.Certificate) error {
		return nil
	})
}

func (p *proofType) GetUnrevokedCertificatesSignedByCAs(domain string, caAuthorityKeyIdentifiers [][]byte) [][]x509.Certificate {
	return p.getUnrevokedCertificates(domain, func(c []x509.Certificate) error {
		if isSignedByCAs(c, caAuthorityKeyIdentifiers) {
			return nil
		}
		return fmt.Errorf("%s is not signed by trusted CA", common.X509CertChainToString(c))
	})
}

// http://thrtle.com
func (p *proofType) getUnrevokedCertificates(domain string, f func([]x509.Certificate) error) [][]x509.Certificate {
	var certs [][]x509.Certificate
	for _, e := range p.mapEntries {
		for _, c := range e.Certificates {
			if _, err := common.X509Verify(c); err != nil {
				common.Debug("%s cannot be verified: %s", common.X509CertChainToString(c), err)
				break
			}
			if err := f(c); err != nil {
				common.Debug(err.Error())
				break
			}
			if isRevoked(c, e.Revocations) {
				common.Debug("%s is revoked", common.X509CertChainToString(c))
				break
			}
			domains := common.DomainsFromX509Cert(&c[0])
			for i, d := range domains {
				if common.IsDomainContainedIn(domain, d) {
					if !containsCertificateChain(certs, c) {
						certs = append(certs, c)
					} else {
						// common.Debug("%s is already added", common.X509CertChainToString(c))
					}
					break
				}
				if i == len(domains)-1 {
					common.Debug("%s was not added since none of its domains is contained in %s", common.X509CertChainToString(c), domain)
				}
			}
		}
		for _, c := range e.WildcardCertificates {
			if _, err := common.X509Verify(c); err != nil {
				common.Debug("%s cannot be verified: %s", common.X509CertChainToString(c), err)
				break
			}
			if err := f(c); err != nil {
				common.Debug(err.Error())
				break
			}
			if isRevoked(c, e.WildcardRevocations) {
				common.Debug("%s is revoked", common.X509CertChainToString(c))
				break
			}
			domains := common.DomainsFromX509Cert(&c[0])
			for i, d := range domains {
				if common.IsDomainContainedIn(domain, d) {
					if !containsCertificateChain(certs, c) {
						certs = append(certs, c)
					} else {
						// common.Debug("%s is already added", common.X509CertChainToString(c))
					}
					break
				}
				if i == len(domains)-1 {
					common.Debug("%s was not added since none of its domains is contained in %s", common.X509CertChainToString(c), domain)
				}
			}
		}
	}
	return certs
}

func (p *proofType) GetAllCertificates() (certs [][]x509.Certificate) {
	for _, e := range p.mapEntries {
		for _, c := range e.Certificates {
			certs = append(certs, c)
		}
	}
	return
}

func containsCertificateChain(certList [][]x509.Certificate, cert []x509.Certificate) bool {
	for _, c := range certList {
		if len(c) == len(cert) {
			for i, _ := range c {
				if !bytes.Equal(c[i].Raw, cert[i].Raw) {
					break
				}
				if i == len(c)-1 {
					return true
				}
			}
		}
	}
	return false
}

func isSignedByCAs(c []x509.Certificate, caAuthorityKeyIdentifiers [][]byte) bool {
	for _, caAKI := range caAuthorityKeyIdentifiers {
		// if the CA certificate is not added in the certificate chain, the certificate issued by the CA must have its authority key id set (RFC5280, Section 4.2.1.1)
		if bytes.Equal(c[len(c)-1].AuthorityKeyId, caAKI) {
			return true
		}
		// if the CA certificate is added in the certificate chain, the CA certificate must have its subject key id set (RFC5280, Section 4.2.1.2)
		if bytes.Equal(c[len(c)-1].SubjectKeyId, caAKI) {
			return true
		}
	}
	return false
}

func isRevoked(c []x509.Certificate, revocations []RevocationMessageType) bool {
	for _, x := range c {
		for _, r := range revocations {
			if r.SerialNumber.Cmp(x.SerialNumber) == 0 {
				return true
			}
		}
	}
	return false
}

func (p *InclusionProofType) MarshalBinary() (data []byte, err error) {
	if len(*p) > 256 {
		return nil, fmt.Errorf("Inclusion proof is longer than the allowed size of 256 hashes")
	}
	var emptyOffset, i, l int
	l = len(*p)
	for ; i < l; i++ {
		if !(len((*p)[i]) == 0 || len((*p)[i]) == 32) {
			return nil, fmt.Errorf("Inclusion proof contains wrong sized hash (%d)", len((*p)[i]))
		}
		if len((*p)[i]) > 0 {
			if emptyOffset != i {
				// i-emptyOffset must be smaller than 256 since emptyOffset >= 0 and i < 256
				data = append(data, byte(i-emptyOffset))
			}
			data = append(data, byte(0))
			data = append(data, (*p)[i]...)
			emptyOffset = i + 1
		}
	}
	if emptyOffset != l {
		if l-emptyOffset == 256 {
			data = append(data, byte(0))
		} else {
			data = append(data, byte(l-emptyOffset))
		}
	}
	return
}

func (p *InclusionProofType) UnmarshalBinary(data []byte) (err error) {
	var pNew InclusionProofType
	if len(data) == 1 && data[0] == byte(0) {
		// special case where the proof consists of 256 empty hashes
		for i := 0; i < 256; i++ {
			pNew = append(pNew, []byte{})
		}
	} else {
		// normal case where the number of consecutive empty hashes is always < 256
		var offset int
		for offset < len(data) {
			if data[offset] == 0 {
				if offset+33 > len(data) {
					return fmt.Errorf("Inclusion proof data is incomplete")
				}
				pNew = append(pNew, data[offset+1:offset+33])
				offset = offset + 33
			} else {
				for i := 0; i < int(data[offset]); i++ {
					pNew = append(pNew, []byte{})
				}
				offset = offset + 1
			}
		}
	}
	*p = append(*p, pNew...)
	return
}

func (p *proofType) MarshalBinary() ([]byte, error) {
	data, err := p.marshalBinary()
	if err != nil || !p.enableCompression {
		return data, err
	}

	var b bytes.Buffer
	zw, err := flate.NewWriter(&b, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	defer zw.Close()

	r := bytes.NewReader(data)
	if _, err = io.Copy(zw, r); err != nil {
		return nil, err
	}
	if err = zw.Flush(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (p *proofType) UnmarshalBinary(data []byte) error {
	if p.enableCompression {
		zr := flate.NewReader(bytes.NewReader(data))
		defer zr.Close()
		var b bytes.Buffer
		if _, err := io.Copy(bufio.NewWriter(&b), zr); err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		data = b.Bytes()
	}
	return p.unmarshalBinary(data)
}

func (p *proofType) marshalBinary() (data []byte, err error) {
	var d proofDataType

	for _, pme := range p.mapEntries {
		me := *pme.toMapEntry()
		meBytes, err := me.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("Couldn't marshal MapEntryType: %s", err)
		}
		d.MapEntries = append(d.MapEntries, meBytes)
	}

	for _, ip := range p.inclusionProofs {
		ipBytes, err := ip.MarshalBinary()
		// ipBytes, err := asn1.Marshal(ip)
		if err != nil {
			return nil, fmt.Errorf("Couldn't marshal InclusionProofType: %s", err)
		}
		d.InclusionProofs = append(d.InclusionProofs, ipBytes)
	}

	signedMapRoot, err := common.MarshalSignedMapRoot(&p.signedMapRoot)
	if err != nil {
		return nil, fmt.Errorf("Couldn't marshal trillian.SignedMapRoot: %s", err)
	}
	d.SignedMapRoot = signedMapRoot

	data, err = asn1.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("Couldn't marshal proofDataType: %s", err)
	}
	return data, nil
}

func (p *proofType) unmarshalBinary(data []byte) error {
	p.mapEntries = nil
	p.inclusionProofs = nil

	var d proofDataType
	_, err := asn1.Unmarshal(data, &d)
	if err != nil {
		return fmt.Errorf("Couldn't unmarshal proofDataType: %s", err)
	}

	for _, meBytes := range d.MapEntries {
		var me MapEntryType
		err := me.UnmarshalBinary(meBytes)
		if err != nil {
			return fmt.Errorf("Couldn't unmarshal MapEntryType: %s", err)
		}

		var pme proofMapEntryType
		pme.fromMapEntry(&me)
		p.mapEntries = append(p.mapEntries, pme)
	}

	for _, ipBytes := range d.InclusionProofs {
		var ip InclusionProofType
		// _, err := asn1.Unmarshal(ipBytes, &ip)
		err := ip.UnmarshalBinary(ipBytes)
		if err != nil {
			return fmt.Errorf("Couldn't unmarshal InclusionProofType: %s", err)
		}
		p.inclusionProofs = append(p.inclusionProofs, ip)
	}

	err = common.UnmarshalSignedMapRoot(d.SignedMapRoot, &p.signedMapRoot)
	if err != nil {
		return fmt.Errorf("Couldn't unmarshal trillian.SignedMapRoot: %s", err)
	}

	return nil
}

func (p *InclusionProofType) ToString() string {
	out := "<InclusionProofType ["
	for i, e := range *p {
		if i != 0 {
			out += ", "
		}
		out += fmt.Sprintf("[%d]", len(e))
	}
	out += "]>"
	return out
}

func (p *proofDataType) ToString() string {
	out := "<proofDataType MapEntries=["
	for i, e := range p.MapEntries {
		if i != 0 {
			out += ", "
		}
		out += fmt.Sprintf("%d", len(e))
	}
	out += "], InclusionProofs=["
	for i, e := range p.InclusionProofs {
		if i != 0 {
			out += ", "
		}
		out += fmt.Sprintf("%d", len(e))
	}
	out += "], SignedMapRoot=["
	out += fmt.Sprintf("%d", len(p.SignedMapRoot))
	out += "]>"
	return out
}

func (p *proofType) IsProofOfPresence() bool {
	return p.exists(len(p.mapEntries) - 1)
}

func (p *proofType) SetDomain(domain string) error {
	labels, err := common.SplitE2LD(domain)
	if err != nil {
		return fmt.Errorf("Couldn't split domain: %s", err)
	}
	if common.IsWildcardDomain(domain) {
		if len(labels)-1 != len(p.mapEntries) {
			return fmt.Errorf("Wrong number of subdomains for wildcard domain '%s' (%d != %d)", domain, len(labels)-1, len(p.mapEntries))
		}
	} else {
		if len(labels) != len(p.mapEntries) {
			return fmt.Errorf("Wrong number of subdomains for domain '%s' (%d != %d)", domain, len(labels), len(p.mapEntries))
		}
	}
	for i, _ := range p.mapEntries {
		p.mapEntries[i].domain = labels[len(labels)-i-1]
	}
	return nil
}

func (p *proofType) GetDomain() string {
	labels := make([]string, len(p.mapEntries))
	for i, e := range p.mapEntries {
		labels[len(labels)-i-1] = e.domain
	}
	return strings.Join(labels, ".")
}

func (p *proofType) GetNumberOfEntries() int {
	return len(p.mapEntries)
}

func (p *proofType) GetEntry(level int) MapEntry {
	if level < 0 || len(p.mapEntries) <= level {
		log.Fatalf("Invalid level %d, must in [0, %d)", level, len(p.mapEntries))
	}
	return &p.mapEntries[level]
}

func (p *proofType) Validate(mapID int64, mapPK crypto.PublicKey, treeNonce []byte, domain string) error {
	//TODO(cyrill) integrate treeNonce into existing proof so we don't have to provide it
	// verify map root signature
	root, err := extractMapRoot(&p.signedMapRoot, mapPK, true)
	if err != nil {
		return err
	}

	labels, err := common.SplitE2LD(domain)
	if err != nil {
		return fmt.Errorf("Couldn't split domain into subdomains: %s", err)
	}

	// wildcard certificates and revocations are stored in the entry for the parent domain
	if common.IsWildcardLabel(labels[0]) {
		labels = labels[1:]
	}

	if len(labels) < len(p.mapEntries) {
		return fmt.Errorf("Domain %s (%d labels) does not fit the proof structure (%d labels)", labels, len(labels), len(p.mapEntries))
	}
	labels = labels[len(labels)-len(p.mapEntries):]

	// verify inclusion proofs
	if len(p.mapEntries) != len(p.inclusionProofs) {
		return fmt.Errorf("The number of labels (%d) is not equal to the number of inclusion proofs (%d)", len(p.mapEntries), len(p.inclusionProofs))
	}
	rootHash := root.RootHash
	for i, e := range p.mapEntries {
		// generate the leaf value
		var leafValue []byte
		if p.exists(i) {
			// construct the leaves
			leafValue, err = e.MarshalBinary()
			if err != nil {
				return err
			}
		} else {
			// use empty leaf value to indicate a non-existing leaf
			if i != len(p.mapEntries)-1 {
				return fmt.Errorf("Only the last label can be marked as non-existant")
			}
		}

		// generate the index (proof is validating starting at the outer-most domain)
		label := labels[len(p.mapEntries)-1-i]
		index := common.GenerateMapKey(treeNonce, label)

		// calculate the leaf hash
		leafHash := maphasher.Default.HashLeaf(mapID, index, leafValue)

		// mapLeaf.extraData and mapID is irrelevant for verifying the inclusion proof
		mapLeaf := &trillian.MapLeaf{Index: index, LeafHash: leafHash, LeafValue: leafValue, ExtraData: nil}

		// verify the inclusion proof
		if err := merkle.VerifyMapInclusionProof(0, mapLeaf, rootHash, p.inclusionProofs[i], maphasher.Default); err != nil {
			return fmt.Errorf("Inclusion proof for label %s at level %d cannot be verified: %s", label, i, err)
		}
		rootHash = e.SubtreeRoot
	}
	return nil
}

func (p *proofType) ToString() string {
	var out, suffix string

	out += "<Proof "
	if p.IsProofOfPresence() {
		out += "PoP "
	} else {
		out += "PoA "
	}
	for i, e := range p.mapEntries {
		var certSize int
		for _, c := range e.Certificates {
			for _, x := range c {
				certSize += len(x.Raw)
			}
		}

		data, _ := p.inclusionProofs[i].MarshalBinary()

		if i == 0 {
			suffix = e.domain
		} else {
			suffix = e.domain + "." + suffix
			out += ", "
		}
		ctr := 0
		for _, h := range p.inclusionProofs[i] {
			if len(h) > 0 {
				ctr += 1
			}
		}
		if p.exists(i) {
			out += fmt.Sprintf("[%s: %d certs, %d wCerts, %d Rev, %d wRev, cSize=%d, pSize(%d)=%d]", suffix, len(e.Certificates), len(e.WildcardCertificates), len(e.Revocations), len(e.WildcardRevocations), certSize, ctr, len(data))
		} else {
			out += fmt.Sprintf("[%s: EMPTY, pSize=%d]", suffix, ctr)
		}
	}
	return out + ">"
}

func (pme *proofMapEntryType) fromMapEntry(me *MapEntryType) {
	pme.Certificates = make([][]x509.Certificate, len(me.Certificates))
	pme.Revocations = make([]RevocationMessageType, len(me.Revocations))
	pme.WildcardCertificates = make([][]x509.Certificate, len(me.WildcardCertificates))
	pme.WildcardRevocations = make([]RevocationMessageType, len(me.WildcardRevocations))
	pme.SubtreeRoot = make([]byte, len(me.SubtreeRoot))

	copy(pme.Certificates, me.Certificates)
	copy(pme.Revocations, me.Revocations)
	copy(pme.WildcardCertificates, me.WildcardCertificates)
	copy(pme.WildcardRevocations, me.WildcardRevocations)
	copy(pme.SubtreeRoot, me.SubtreeRoot)
}

func (pme *proofMapEntryType) toMapEntry() *MapEntryType {
	var me MapEntryType
	me.Certificates = make([][]x509.Certificate, len(pme.Certificates))
	me.Revocations = make([]RevocationMessageType, len(pme.Revocations))
	me.WildcardCertificates = make([][]x509.Certificate, len(pme.WildcardCertificates))
	me.WildcardRevocations = make([]RevocationMessageType, len(pme.WildcardRevocations))
	me.SubtreeRoot = make([]byte, len(pme.SubtreeRoot))

	copy(me.Certificates, pme.Certificates)
	copy(me.Revocations, pme.Revocations)
	copy(me.WildcardCertificates, pme.WildcardCertificates)
	copy(me.WildcardRevocations, pme.WildcardRevocations)
	copy(me.SubtreeRoot, pme.SubtreeRoot)
	return &me
}

func (p *proofType) exists(level int) bool {
	if level < 0 || level >= len(p.mapEntries) {
		return false
	}
	e := p.mapEntries[level]
	if len(e.GetCertificates()) > 0 {
		return true
	}
	if len(e.GetWildcardCertificates()) > 0 {
		return true
	}
	if len(e.GetRevocations()) > 0 {
		return true
	}
	if len(e.GetWildcardRevocations()) > 0 {
		return true
	}
	if len(e.GetSubtreeRoot()) > 0 {
		return true
	}
	return false
}
