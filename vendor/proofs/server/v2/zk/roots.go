package zk

import "crypto/x509"

var (
	// IssuerRoots is a pool of trusted root certificate authorities.
	IssuerRoots = x509.NewCertPool()
)
