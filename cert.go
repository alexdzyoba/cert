package main

import (
	"bytes"
	"crypto/x509"
	"time"

	"github.com/pkg/errors"
)

const PEMCertType = "CERTIFICATE"

// Cert wraps x509.Certificate for enhanced output
type Cert struct {
	*x509.Certificate
	isRoot    bool
	verified  bool
	verifyErr error
}

func FromX509(cert *x509.Certificate) (*Cert, error) {
	return &Cert{
		Certificate: cert,
	}, nil
}

func FromBytes(bytes []byte) (*Cert, error) {
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse certificate")
	}

	return &Cert{
		Certificate: cert,
	}, nil
}

// matchRoots checks if the given cert is in the roots pool
func matchRoots(cert *x509.Certificate, roots *x509.CertPool) bool {
	for _, r := range roots.Subjects() {
		if bytes.Equal(r, cert.RawSubject) {
			return true
		}
	}
	return false
}

// Bundle is a list of certificates.
type Bundle []*Cert

func (cs Bundle) Verify(asChain bool, t time.Time, roots *x509.CertPool) error {
	var err error
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return err
		}
	}

	// Verify every cert in the chain by iterating from the tail.
	// This allows verifying at least chain part.
	for i := len(cs) - 1; i >= 0; i-- {
		if asChain {
			err = verifyChainPart(cs[i:], t, roots)
		} else {
			err = verifyCert(cs[i], t, roots)
		}

		if err == nil {
			cs[i].verified = true
		} else {
			cs[i].verifyErr = err
		}

		cs[i].isRoot = matchRoots(cs[i].Certificate, roots)
	}
	return nil
}

// verifyChainPart iterates over slice of certificates in chain
// and verifies the first cert using other certs as intermediates.
func verifyChainPart(chain []*Cert, t time.Time, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()

	for _, c := range chain[1:] {
		intermediates.AddCert(c.Certificate)
	}

	_, err := chain[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   t,
		Roots:         roots,
	})

	return err
}

func verifyCert(cert *Cert, t time.Time, roots *x509.CertPool) error {
	_, err := cert.Verify(x509.VerifyOptions{
		CurrentTime: t,
		Roots:       roots,
	})
	return err
}
