// This file holds definitions related to Certificate Update

package common

import (
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/google/certificate-transparency-go/tls"
)

type CUReq struct {
	EECert    ByteEECert `json:"eecert"`
	OldEECert ByteEECert `json:"old_eecert"`
	FirstCA   string     `json:"first_ca"`
	SecondCA  string     `json:"second_ca"`
	FirstILS  string     `json:"first_ils"`
	Signature Signature  `json:"signature"`
}

func (cur *CUReq) ToVerify() CUReq {
	return CUReq{EECert: cur.EECert, OldEECert: cur.OldEECert, FirstCA: cur.FirstCA, SecondCA: cur.SecondCA, FirstILS: cur.FirstILS}
}

type UAccept struct {
	EECertHash []byte               `json:"eecert_hash"`
	Timestamp int64                 `json:"timestamp"`
	Signatures map[string]Signature `json:"signatures"`
}

func (ua *UAccept) ToVerify() UAccept {
	return UAccept{EECertHash: ua.EECertHash, Timestamp: ua.Timestamp}
}


func (ua *UAccept) VerifySignatures(publicKeys map[string]crypto.PublicKey) (bool, error) {
	for id, sig := range ua.Signatures {
		jsonUAccept, err := json.Marshal(ua.ToVerify())
		if err != nil {
			return false, fmt.Errorf("failed to marshal UAccept %s: %s", id, err)
		}

		err = tls.VerifySignature(publicKeys[id], jsonUAccept, tls.DigitallySigned(sig))
		if err != nil {
			return false, fmt.Errorf("failed to verify UAccept signature %s: %s", id, err)
		}
	}

	return true, nil
}

type CUResp struct {
	UAccept   UAccept   `json:"uaccept"`
	CUReq     CUReq     `json:"cureq"`
	SynAcks   []SynAck  `json:"synacks"`
	Signature Signature `json:"signature"`
}

func (cursp *CUResp) ToVerify() CUResp {
	return CUResp{UAccept: cursp.UAccept, CUReq: cursp.CUReq, SynAcks: cursp.SynAcks}
}

type CUConf struct {
	FirstCA   string    `json:"first_ca"`
	SecondCA  string    `json:"second_ca"`
	FirstILS  string    `json:"first_ils"`
	UAccept   UAccept   `json:"uaccept"`
	SynAcks   []SynAck  `json:"synacks"`
	Signature Signature `json:"signature"`
}

func (cuc *CUConf) ToVerify() CUConf {
	return CUConf{FirstCA: cuc.FirstCA, SecondCA: cuc.SecondCA, FirstILS: cuc.FirstILS, UAccept: cuc.UAccept, SynAcks: cuc.SynAcks}
}