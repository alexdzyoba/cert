package main

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

type Certificate struct {
	raw         *x509.Certificate
	fingerprint [32]byte
}

// NewCertificate creates a certificate from DER-encoded data block
func NewCertificate(data []byte) (*Certificate, error) {
	raw, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return NewCertificateFromX509(raw)
}

func NewCertificateFromX509(raw *x509.Certificate) (*Certificate, error) {
	fingerprint := sha256.Sum256(raw.Raw)
	return &Certificate{raw, fingerprint}, nil
}

type Bundle []*Certificate
