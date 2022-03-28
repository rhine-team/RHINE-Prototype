// This file holds definitions related to Certificate Confirmation

package common

type CCReq struct {
	FirstCA   string     `json:"first_ca"`
	SecondCA  string     `json:"second_ca"`
	FirstILS  string     `json:"first_ils"`
	EECert    ByteEECert `json:"eecert"`
	Signature Signature  `json:"signature"`
}

func (ccr *CCReq) ToVerify() CCReq {
	return CCReq{FirstCA: ccr.FirstCA, SecondCA: ccr.SecondCA, FirstILS: ccr.FirstILS, EECert: ccr.EECert}
}

type CCResp struct {
	CCReq    CCReq               `json:"ccreq"`
	PoP      Proof               `json:"pop"`
	MultiSMR *MultiSignedMapRoot `json:"msmr"`
}

type CCConf struct {
	PoP      Proof               `json:"pop"`
	MultiSMR *MultiSignedMapRoot `json:"msmr"`
}