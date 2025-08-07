package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

type TextBundlePrinter struct {
	level Level
	now   time.Time
}

type Level int

const (
	BaseLevel = iota
	VerboseLevel
	FullLevel
)

type Opt func(*TextBundlePrinter)

func WithLevel(l Level) Opt {
	return func(p *TextBundlePrinter) {
		p.level = l
	}
}

func WithTime(t time.Time) Opt {
	return func(p *TextBundlePrinter) {
		p.now = t
	}
}

func NewTextBundlePrinter(opts ...Opt) *TextBundlePrinter {
	p := new(TextBundlePrinter)
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p TextBundlePrinter) Print(bundle Bundle) (string, error) {
	var b strings.Builder
	for i, c := range bundle {
		if i > 0 {
			fmt.Fprintln(&b)
		}
		fmt.Fprintf(&b, "[%d] Certificate:\n", i)
		fmt.Fprint(&b, p.printCert(c))
	}

	return b.String(), nil
}

func (p TextBundlePrinter) printCert(cert *Cert) string {
	var b strings.Builder

	fmt.Fprintf(&b, "serial number: %s\n", cert.SerialNumber)
	fmt.Fprintf(&b, "subject: %s\n", cert.Subject)
	fmt.Fprintf(&b, "issuer: %s\n", cert.Issuer)
	fmt.Fprintf(&b, "isCA: %v\n", cert.IsCA)
	fmt.Fprintf(&b, "root: %v\n", cert.isRoot)

	format := "2006-01-02 15:04:05"
	fmt.Fprintln(&b, "valid:")
	fmt.Fprintf(&b, "  from: %v\n", cert.NotBefore.Local().Format(format))
	fmt.Fprintf(&b, "  to  : %v\n", cert.NotAfter.Local().Format(format))

	if len(cert.DNSNames) > 0 || len(cert.EmailAddresses) > 0 || len(cert.IPAddresses) > 0 || len(cert.URIs) > 0 {
		fmt.Fprintln(&b, "Subject Alternative Names:")
	}

	if len(cert.DNSNames) > 0 {
		fmt.Fprintf(&b, "  DNS: %v\n", cert.DNSNames)
	}

	if len(cert.EmailAddresses) > 0 {
		fmt.Fprintf(&b, "  Emails: %v\n", cert.EmailAddresses)
	}

	if len(cert.IPAddresses) > 0 {
		fmt.Fprintf(&b, "  IPs: %v\n", cert.IPAddresses)
	}

	if len(cert.URIs) > 0 {
		fmt.Fprintf(&b, "  URIs: %v\n", cert.URIs)
	}

	if cert.verified {
		fmt.Fprintf(&b, "verified: %s\n", color.GreenString("✔"))
	} else {
		fmt.Fprintf(&b, "verified: %s (%s)\n", color.RedString("✖"), cert.verifyErr)
	}
	return b.String()

}
