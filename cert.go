package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

// Cert wraps x509.Certificate for enhanced output
type Cert struct {
	x509.Certificate
	verified bool
	isRoot   bool
}

func FromX509Cert(cert *x509.Certificate) (*Cert, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	return &Cert{
		Certificate: *cert,
		verified:    false,
		isRoot:      matchRoots(cert, roots),
	}, nil
}

func FromBytes(bytes []byte) (*Cert, error) {
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse certificate")
	}

	_, err = cert.Verify(x509.VerifyOptions{})
	verified := err == nil

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}

	return &Cert{
		Certificate: *cert,
		verified:    verified,
		isRoot:      matchRoots(cert, roots),
	}, nil
}

func matchRoots(cert *x509.Certificate, roots *x509.CertPool) bool {
	for _, r := range roots.Subjects() {
		if bytes.Equal(r, cert.RawSubject) {
			return true
		}
	}
	return false
}

// Certs represent simple list of certificates that doesn't form chain like the
// list of root certs. It has its own simple string serialization.
type Certs []*Cert

func (cs Certs) String() string {
	var b strings.Builder
	for i, c := range cs {
		fmt.Fprintf(&b, "[%d] Certificate:\n", i)

		fmt.Fprintf(&b, "serial number: %s\n", c.SerialNumber)
		fmt.Fprintf(&b, "subject: %s\n", c.Subject)
		fmt.Fprintf(&b, "issuer: %s\n", c.Issuer)
		fmt.Fprintf(&b, "isCA: %v\n", c.IsCA)
		fmt.Fprintf(&b, "root: %v\n", c.isRoot)

		format := "2006-01-02 15:04:05"
		fmt.Fprintf(&b, "valid: from '%v' to '%v'\n",
			c.NotBefore.Local().Format(format),
			c.NotAfter.Local().Format(format),
		)

		fmt.Fprintln(&b)
	}

	return b.String()
}
