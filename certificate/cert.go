package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/fatih/color"

	"github.com/alexdzyoba/cert/errors"
)

// Cert wraps x509.Certificate for enhanced output
type Cert struct {
	x509.Certificate
	verified bool
}

func New(pemData []byte) (*Cert, error) {
	cert, err := x509.ParseCertificate(pemData)
	if err != nil {
		return nil, errors.ParseFailure
	}

	return &Cert{*cert, false}, nil
}

func (c *Cert) Name() string {
	return "Certificate"
}

func (c *Cert) Indent(indent string) string {
	var b strings.Builder

	fmt.Fprintf(&b, indent+"serial number: %s\n", c.SerialNumber)
	fmt.Fprintf(&b, indent+"subject: %s\n", c.Subject)
	fmt.Fprintf(&b, indent+"issuer: %s\n", c.Issuer)

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
