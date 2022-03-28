// This file holds various functions
// used by different entities

package common

import (
	"encoding/csv"
	"fmt"
	"io"
)

type DroppedLogEntry struct {
	CtLogIndex int64
	Error      error
}

type DroppedLogEntryWriter struct {
	Writer *csv.Writer
}

func NewDroppedLogEntryWriter(w io.Writer) *DroppedLogEntryWriter {
	return &DroppedLogEntryWriter{Writer: csv.NewWriter(w)}
}

func (w *DroppedLogEntryWriter) Close() {
	w.Writer.Flush()
}

func (w *DroppedLogEntryWriter) Write(p *DroppedLogEntry) error {
	return w.Writer.Write([]string{fmt.Sprintf("%d", p.CtLogIndex), p.Error.Error()})
}

type ProofPerformanceInfo struct {
	CurrentIdx int64
	Domain     string

	// all certificates including intermediate certificates
	NCertificates int64
	// use to see possible how many overlapping intermediate certificates there are
	NUniqueCertificates int64
	// calculate possible savings from encoding certificates in a smart way
	UniqueCertificatesSize int64

	// see how many domains already adhere to the uniqueness policy
	NLeafCertificates int64
	NUniquePublicKeys int64

	// check how many domains have the same public key for the exact domain (e.g., test.example.com without example.com certificates)
	NLeafCertificatesForExactDomain int64
	NUniquePublicKeysForExactDomain int64
	// check how many wildcard certificates have the same public key (e.g., test.example.com and *.example.com without example.com)
	NLeafCertificatesForExactDomainOrWildcard int64
	NUniquePublicKeysForExactDomainOrWildcard int64

	// time it takes mapClient.GetProofForDomains() to finish in nanonsecods
	GetProofTime int64
	// size of the complete DER encoded proof
	ProofSize int64
	// size of the encoded inclusion proofs
	InclusionProofSize int64
	// size of the compressed DER encoded proof
	CompressedProofSize int64

	// check how many CAs issued certificates
	NUniqueRootCACertificates int64
}

type ProofPerformanceInfoWriter struct {
	Writer *csv.Writer
}

func NewProofPerformanceInfoWriter(w io.Writer) *ProofPerformanceInfoWriter {
	return &ProofPerformanceInfoWriter{Writer: csv.NewWriter(w)}
}

func (w *ProofPerformanceInfoWriter) Close() {
	w.Writer.Flush()
}

func (w *ProofPerformanceInfoWriter) StoreProofPerformanceInfoEntry(p *ProofPerformanceInfo) error {
	return w.Writer.Write([]string{fmt.Sprintf("%d", p.CurrentIdx), p.Domain, fmt.Sprintf("%d", p.NCertificates), fmt.Sprintf("%d", p.NUniqueCertificates), fmt.Sprintf("%d", p.UniqueCertificatesSize), fmt.Sprintf("%d", p.NLeafCertificates), fmt.Sprintf("%d", p.NUniquePublicKeys), fmt.Sprintf("%d", p.NLeafCertificatesForExactDomain), fmt.Sprintf("%d", p.NUniquePublicKeysForExactDomain), fmt.Sprintf("%d", p.NLeafCertificatesForExactDomainOrWildcard), fmt.Sprintf("%d", p.NUniquePublicKeysForExactDomainOrWildcard), fmt.Sprintf("%d", p.GetProofTime), fmt.Sprintf("%d", p.ProofSize), fmt.Sprintf("%d", p.InclusionProofSize), fmt.Sprintf("%d", p.CompressedProofSize), fmt.Sprintf("%d", p.NUniqueRootCACertificates)})
}
