package rhine

import "crypto/x509"

type AuhtorityManager struct {
	ca      Authority
	privkey any
	cacert  *x509.Certificate
}
