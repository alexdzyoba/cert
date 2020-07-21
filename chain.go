package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/pkg/errors"
)

// Chain is a list of certificates that must be verified together
type Chain []*Cert

// NewChain builds a certificate chain from certs and verifies it using given
// time t.
func NewChain(certs Certs, t time.Time, verbose bool) Chain {
	ch := Chain(certs)
	for i := len(ch) - 1; i >= 0; i-- {
		err := verifyChainPart(ch[i:], t)
		if err == nil {
			ch[i].verified = true
		} else {
			if verbose {
				log.Printf("failed to verify chain part at %s: %v", ch[i].Subject, err)
			}
		}
	}

	return ch
}

// verifyChainPart iterates over slice of certificates in chain
// and verifies the first cert using other certs as intermediates.
func verifyChainPart(chain []*Cert, t time.Time) error {
	intermediates := x509.NewCertPool()

	for _, c := range chain[1:] {
		intermediates.AddCert(&c.Certificate)
	}

	_, err := chain[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   t,
	})
	if err != nil {
		return errors.Wrap(err, "x509 chain verify error")
	}

	return nil
}

// String is a fancy serialization for certificate chain
func (ch Chain) String() string {
	indent := "  "

	var b strings.Builder
	for i, c := range ch {
		fmt.Fprintf(&b, "[%d] Certificate:\n", i)

		fmt.Fprintf(&b, indent+"serial number: %s\n", c.SerialNumber)
		fmt.Fprintf(&b, indent+"subject: %s\n", c.Subject)
		fmt.Fprintf(&b, indent+"issuer: %s\n", c.Issuer)
		fmt.Fprintf(&b, indent+"isCA: %v\n", c.IsCA)
		fmt.Fprintf(&b, indent+"root: %v\n", c.isRoot)

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

		fmt.Fprintln(&b)

		indent += "  "
	}

	return b.String()
}
