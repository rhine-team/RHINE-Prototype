package requests

type NewDlgRequest struct {
	Header    *ParentHeader  `json:"header"`
	Payload   *NewDlgPayload `json:"payload"`
	Signature string         `json:"signature"`
}

type NewDlgPayload struct {
	Req_type string `json:"req_type"`
	IndependentSubZone string `json:"ind_sub_zone"`
	Csr      string `json:"csr"`
}

type ParentHeader struct {
	Parent_auth_type string `json:"parent_auth_type"`
	Parent_cert      string `json:"parent_cert,omitempty"`
	Alg              string `json:"alg"`
	Pubkey           string `json:"pubkey"`
}

type CAResponse struct {
	Cert  string `json:"cert, omitempty"`
	Error string `json:"error, omitempty"`
}

type CheckNewDlgRequest struct {
	Header    *ParentHeader
	Payload   *CheckNewDlgPayload `json:"payload"`
	Signature string              `json:"signature"`
}
type CheckNewDlgPayload struct {
	Cert               string `json:"cert"`
}

type CheckResponse struct {
	Status		string `json:"status"`
	Error 		string `json:"error"`
}

type ReNewDlgRequest struct {
	Csr  		string `json:"csr"`
}

type CheckReNewDlgRequest struct {
	Cert    string `json:"cert"`
	Signature string  `json:"signature"`
}

type KeyChangeDlgRequest struct {
	Csr  		string `json:"csr"`
	OldKeyAlg   string `json:"old_key_alg"`
	OldKey   string `json:"old_key"`
	Signature string  `json:"signature"`
}

type CheckKeyChangeDlgRequest struct {
	Cert    string `json:"cert"`
	OldKeyAlg   string `json:"old_key_alg"`
	OldKey   string `json:"old_key"`
	Signature string  `json:"signature"`
}

type RevokeDlgRequest struct {
	Cert string `json:"cert"`
	Signature string `json:"signature"`
}

