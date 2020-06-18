package certificate

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/pkg/errors"
)

// Cert wraps x509.Certificate for enhanced output
type Cert struct {
	x509.Certificate
	verified bool
	root     bool
}

func New(pemData []byte) (*Cert, error) {
	cert, err := x509.ParseCertificate(pemData)
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
		root:        matchRoots(cert, roots),
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

func (c *Cert) Name() string {
	return "Certificate"
}

func (c *Cert) Indent(indent string) string {
	var b strings.Builder

	fmt.Fprintf(&b, indent+"serial number: %s\n", c.SerialNumber)
	fmt.Fprintf(&b, indent+"subject: %s\n", c.Subject)
	fmt.Fprintf(&b, indent+"issuer: %s\n", c.Issuer)
	fmt.Fprintf(&b, indent+"isCA: %v\n", c.IsCA)
	fmt.Fprintf(&b, indent+"root: %v\n", c.root)

	format := "2006-01-02 15:04:05"
	fmt.Fprintf(&b, indent+"valid: from '%v' to '%v'\n",
		c.NotBefore.Local().Format(format),
		c.NotAfter.Local().Format(format),
	)

	if c.verified {
		fmt.Fprintf(&b, indent+"verified: %s\n", color.GreenString("✔"))
	} else {
		fmt.Fprintf(&b, indent+"verified: %s\n", color.RedString("✖"))
	}

	return b.String()
}
