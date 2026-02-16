package main

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

// Record holds verification results for a single certificate.
type Record struct {
	Cert   *Certificate
	Error  error
	IsRoot bool

	Validity Validity
}

type Validity struct {
	OK          bool
	NotBeforeOK bool
	NotAfterOK  bool
	Period      Duration
	ExpiresIn   Duration
}

func NewRecord(cert *Certificate, err error, opts *VerifyOptions) *Record {
	return &Record{
		Cert:   cert,
		Error:  err,
		IsRoot: isRootCert(cert, opts.Roots),
		Validity: Validity{
			OK:          isValid(cert.inner, opts.Time),
			NotBeforeOK: opts.Time.After(cert.inner.NotBefore),
			NotAfterOK:  opts.Time.Before(cert.inner.NotAfter),
			Period:      validity(cert.inner),
			ExpiresIn:   expiresIn(cert.inner, opts.Time),
		},
	}
}

func (r *Record) String() string {
	var parts []string
	parts = append(parts, "Record{")
	if r.Cert != nil {
		parts = append(parts, fmt.Sprintf("  Cert: %s", r.Cert.String()))
	} else {
		parts = append(parts, "  Cert: <nil>")
	}
	if r.Error != nil {
		parts = append(parts, fmt.Sprintf("  Error: %v", r.Error))
	} else {
		parts = append(parts, "  Error: <nil>")
	}
	parts = append(parts, fmt.Sprintf("  IsRoot: %t", r.IsRoot))
	parts = append(parts, fmt.Sprintf("  Valid: %t", r.Validity.OK))
	parts = append(parts, fmt.Sprintf("  Validity: %s", r.Validity.Period))
	parts = append(parts, fmt.Sprintf("  ExpiresIn: %s", r.Validity.ExpiresIn))
	parts = append(parts, "}")
	return strings.Join(parts, "\n")
}

// Report is a collection of verification records for a certificate chain.
type Report []*Record

func (r Report) String() string {
	var parts []string
	parts = append(parts, "Report{")
	for i, rec := range r {
		recStr := rec.String()
		lines := strings.Split(recStr, "\n")
		parts = append(parts, fmt.Sprintf("  [%d]: %s", i, lines[0]))
		for _, line := range lines[1:] {
			parts = append(parts, "  "+line)
		}
	}
	parts = append(parts, "}")
	return strings.Join(parts, "\n")
}

func isRootCert(cert *Certificate, roots Bundle) bool {
	return false
}

func isValid(cert *x509.Certificate, t time.Time) bool {
	return t.After(cert.NotBefore) && t.Before(cert.NotAfter)
}

func validity(cert *x509.Certificate) Duration {
	return Duration(cert.NotAfter.Sub(cert.NotBefore))
}

func expiresIn(cert *x509.Certificate, t time.Time) Duration {
	return Duration(cert.NotAfter.Sub(t))
}
