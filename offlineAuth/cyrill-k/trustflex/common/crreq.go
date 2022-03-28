// This file holds definitions related to Certificate Registration

package common

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/google/certificate-transparency-go/tls"
	"strconv"
)

type CRReq struct {
	EECert    ByteEECert `json:"eecert"`
	FirstCA   string     `json:"first_ca"`
	SecondCA  string     `json:"second_ca"`
	FirstILS  string     `json:"first_ils"`
	Signature Signature  `json:"signature"`
}

func (crr *CRReq) ToVerify() CRReq {
	return CRReq{EECert: crr.EECert, FirstCA: crr.FirstCA, SecondCA: crr.SecondCA, FirstILS: crr.FirstILS}
}

type Accept struct {
	EECertHash []byte               `json:"eecert_hash"`
	Timestamp int64                 `json:"timestamp"`
	Signatures map[string]Signature `json:"signatures"`
}

func (a *Accept) ToVerify() Accept {
	return Accept{EECertHash: a.EECertHash, Timestamp: a.Timestamp}
}

func (a *Accept) VerifySignatures(publicKeys map[string]crypto.PublicKey) (bool, error) {
	for id, sig := range a.Signatures {
		jsonAccept, err := json.Marshal(a.ToVerify())
		if err != nil {
			return false, fmt.Errorf("failed to marshal Accept %s: %s", id, err)
		}

		err = tls.VerifySignature(publicKeys[id], jsonAccept, tls.DigitallySigned(sig))
		if err != nil {
			return false, fmt.Errorf("failed to verify Accept signature %s: %s", id, err)
		}
	}

	return true, nil
}

type CRResp struct {
	Accept    Accept    `json:"accept"`
	CRReq     CRReq     `json:"crreq"`
	SynAcks   []SynAck  `json:"syn_acks"`
	Signature Signature `json:"signature"`
}

func (crrsp *CRResp) ToVerify() CRResp {
	return CRResp{Accept: crrsp.Accept, CRReq: crrsp.CRReq, SynAcks: crrsp.SynAcks}
}

type CRConf struct {
	FirstCA   string    `json:"first_ca"`
	SecondCA  string    `json:"second_ca"`
	FirstILS  string    `json:"first_ils"`
	Accept    Accept    `json:"accept"`
	SynAcks   []SynAck  `json:"syn_acks"`
	Signature Signature `json:"signature"`
}

func (crc *CRConf) ToVerify() CRConf {
	return CRConf{FirstCA: crc.FirstCA, SecondCA: crc.SecondCA, FirstILS: crc.FirstILS, Accept: crc.Accept, SynAcks: crc.SynAcks}
}

type SynReq struct {
	CoordId   string    `json:"coord_id"`
	Request   CRReq     `json:"cr_req"`
	Type      int       `json:"type"`
	Signature Signature `json:"hash_sig"`
}

func (s *SynReq) VerifySignature(certificate *x509.Certificate) error {
	pubKey := certificate.PublicKey
	fields := AppendToByteSlice(s.Request, s.CoordId, strconv.Itoa(s.Type), "Node failed to marshal CRReq in SYN-REQ: %s")
	return tls.VerifySignature(pubKey, fields, tls.DigitallySigned(s.Signature))
}

type SynResp struct {
	Hash      []byte    `json:"hashed_req"`
	Signature Signature `json:"syn_resp_signature"`
}

func (s *SynResp) VerifySignature(certificate *x509.Certificate) error {
	pubKey := certificate.PublicKey
	return tls.VerifySignature(pubKey, s.Hash, tls.DigitallySigned(s.Signature))
}

type SynCommit struct {
	Hash      []byte    `json:"hashed_req"`
	Signature Signature `json:"syn_commit_signature"`
}

func (s *SynCommit) VerifySignature(certificate *x509.Certificate) error {
	pubKey := certificate.PublicKey
	return tls.VerifySignature(pubKey, s.Hash, tls.DigitallySigned(s.Signature))
}

type SynAck struct {
	ID        string    `json:"id"`
	Hash      []byte    `json:"hashed_req"`
	Signature Signature `json:"syn_ack_signature"`
}

func (s *SynAck) VerifySignature(certificate *x509.Certificate) error {
	pubKey := certificate.PublicKey
	return  tls.VerifySignature(pubKey, s.Hash, tls.DigitallySigned(s.Signature))
}
