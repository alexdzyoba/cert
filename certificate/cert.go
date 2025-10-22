package certificate

import "crypto/x509"

type Cert struct {
	raw         *x509.Certificate
	fingerprint [32]byte
}

type Bundle []*Cert
