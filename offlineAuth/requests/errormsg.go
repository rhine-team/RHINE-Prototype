package requests


const (
	CsrDecodeError = iota
	CertDecodeError
	CsrParseError
	CertParseError
	CsrSignatureInvalid
	CsrSANDNSMissing
	ParentAuthDNSSECFailed
	ParentAuthCertDecodeError
	ParentAuthCertParseError
	ParentAuthCertInvalid
	MapServerConnectionFailed
	AuthTypeMissing
	InvalidSignature
	ConflictingCertInLog
	CertIssueError
	RequiredCertNotInLog
	OldKeyDecodeError
	JSONDecodeError
	ParentCertificateMissing
	CSRMissing
	UnsupportedAlg
	CertInvalid

)

var ErrorMsg = map[int]string {
	CsrDecodeError:            "Csr Decode Error",
	CertDecodeError: "Cert Decode Error",
	CsrParseError:             "Csr Parse Error",
	CertParseError: "Cert Parse Error",
	CsrSignatureInvalid:       "Csr Signature Invalid",
	CsrSANDNSMissing:          "Csr SAN DNS Missing",
	ParentAuthDNSSECFailed:    "Parent Auth DNSSEC Failed",
	ParentAuthCertDecodeError: "Parent Auth Cert Decode Error",
	ParentAuthCertParseError:  "Parent Auth Cert Parse Error",
	ParentAuthCertInvalid:     "Parent Auth Cert Invalid",
	MapServerConnectionFailed: "Map Server Connection Failed",
	AuthTypeMissing: "Auth Type Missing",
	InvalidSignature: "Invalid Signature",
	ConflictingCertInLog: "Conflicting Cert In Log",
	CertIssueError: "Cert Issue Error",
	RequiredCertNotInLog: "Required Cert Not In Log",
	OldKeyDecodeError: "Old Key Decode Error",
	JSONDecodeError: "JSON Decode Error",
	ParentCertificateMissing: "Parent Certificate Missing",
	CSRMissing: "CSR Missing",
	UnsupportedAlg: "Unsupported Alg",
	CertInvalid: "Certificate Invalid",

}
