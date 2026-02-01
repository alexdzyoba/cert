package main

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

// Certificate wraps an x509.Certificate with additional metadata.
type Certificate struct {
	inner       *x509.Certificate
	fingerprint Fingerprint
}

// Fingerprint is a SHA-256 hash of a certificate's DER-encoded form.
type Fingerprint [32]byte

// NewCertificate creates a certificate from DER-encoded data block
func NewCertificate(data []byte) (*Certificate, error) {
	inner, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return NewCertificateFromX509(inner)
}

// NewCertificateFromX509 creates a Certificate from an existing x509.Certificate.
func NewCertificateFromX509(inner *x509.Certificate) (*Certificate, error) {
	fingerprint := sha256.Sum256(inner.Raw)
	return &Certificate{inner, fingerprint}, nil
}

// Bytes returns the DER-encoded form of the certificate.
func (c *Certificate) Bytes() []byte {
	return c.inner.Raw
}

func (c *Certificate) String() string {
	return fmt.Sprintf("Certificate{Subject: %s, Issuer: %s, NotBefore: %s, NotAfter: %s, Fingerprint: %x}",
		c.inner.Subject.String(),
		c.inner.Issuer.String(),
		c.inner.NotBefore.Format("2006-01-02 15:04:05"),
		c.inner.NotAfter.Format("2006-01-02 15:04:05"),
		c.fingerprint)
}

// Bundle is an ordered collection of certificates, typically representing a chain.
type Bundle []*Certificate
