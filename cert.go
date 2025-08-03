package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
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

func (c Cert) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "serial number: %s\n", c.SerialNumber)
	fmt.Fprintf(&b, "subject: %s\n", c.Subject)
	fmt.Fprintf(&b, "issuer: %s\n", c.Issuer)
	fmt.Fprintf(&b, "isCA: %v\n", c.IsCA)
	fmt.Fprintf(&b, "root: %v\n", c.isRoot)

	format := "2006-01-02 15:04:05"
	fmt.Fprintln(&b, "valid:")
	fmt.Fprintf(&b, "  from: %v\n", c.NotBefore.Local().Format(format))
	fmt.Fprintf(&b, "  to  : %v\n", c.NotAfter.Local().Format(format))

	if len(c.DNSNames) > 0 || len(c.EmailAddresses) > 0 || len(c.IPAddresses) > 0 || len(c.URIs) > 0 {
		fmt.Fprintln(&b, "Subject Alternative Names:")
	}

	if len(c.DNSNames) > 0 {
		fmt.Fprintf(&b, "  DNS: %v\n", c.DNSNames)
	}

	if len(c.EmailAddresses) > 0 {
		fmt.Fprintf(&b, "  Emails: %v\n", c.EmailAddresses)
	}

	if len(c.IPAddresses) > 0 {
		fmt.Fprintf(&b, "  IPs: %v\n", c.IPAddresses)
	}

	if len(c.URIs) > 0 {
		fmt.Fprintf(&b, "  URIs: %v\n", c.URIs)
	}

	if c.verified {
		fmt.Fprintf(&b, "verified: %s\n", color.GreenString("✔"))
	} else {
		fmt.Fprintf(&b, "verified: %s (%s)\n", color.RedString("✖"), c.verifyErr)
	}
	return b.String()
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

func (cs Bundle) String() string {
	var b strings.Builder
	for i, c := range cs {
		if i > 0 {
			fmt.Fprintln(&b)
		}
		fmt.Fprintf(&b, "[%d] Certificate:\n", i)
		fmt.Fprint(&b, c)
	}

	return b.String()
}

func (cs Bundle) Verify(asChain bool, t time.Time, roots *x509.CertPool) error {
	var err error
	if roots == nil {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return err
		}
	}

	// Verify every cert in the chain by iterating from the tail.
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

func (b Bundle) AsPEM() (string, error) {
	var (
		s   strings.Builder
		err error
	)

	for _, cert := range b {
		err = pem.Encode(&s, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return "", fmt.Errorf("cannot encode cert %v: %w", cert.Subject, err)
		}
	}

	return s.String(), nil
}
