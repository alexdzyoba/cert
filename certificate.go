package main

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

type Certificate struct {
	inner       *x509.Certificate
	fingerprint [32]byte
}

// NewCertificate creates a certificate from DER-encoded data block
func NewCertificate(data []byte) (*Certificate, error) {
	inner, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return NewCertificateFromX509(inner)
}

func NewCertificateFromX509(inner *x509.Certificate) (*Certificate, error) {
	fingerprint := sha256.Sum256(inner.Raw)
	return &Certificate{inner, fingerprint}, nil
}

func (c *Certificate) Bytes() []byte {
	return c.inner.Raw
}

type Bundle []*Certificate
