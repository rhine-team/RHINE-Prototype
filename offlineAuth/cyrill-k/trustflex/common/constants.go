package common

const (
	HTTPS         = "https://"
	Local         = "localhost"
	BaseURL       = HTTPS + Local
	ILSPathPrefix = "/ils/"
	CAPathPrefix  = "/ca/"

	ILSCRReqPath      = "cr-req"
	ILSCCReqPath      = "cc-req"
	ILSCUReqPath      = "cu-req"
	ILSGetPoAPath     = "get-poa"
	ILSGetRootsPath   = "get-roots"
	ILSPoCPath        = "get-poc"
	ILSGetEntriesPath = "get-entries"

	CACRReqPath = "cr-req"
	CRRespPath  = "cr-resp"
	CRConfPath  = "cr-conf"

	CACCReqPath = "cc-req"
	CCPopPath   = "cc-pop"
	CACCPopPath = "ca-cc-pop"

	CACUReqPath  = "cu-req"
	CACURespPath = "cu-resp"
	CACUConfPath = "cu-conf"

	ContentTypeHeader = "Content-Type"
	AppJsonHeader     = "application/json"

	N      = 3
	Ilses  = 2
	Quorum = 1
)

var DefaultTreeNonce []byte = make([]byte, 32)
