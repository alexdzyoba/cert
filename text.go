package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
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

var (
	cell = lipgloss.NewStyle().Padding(0, 1)
	box  = cell.Border(lipgloss.NormalBorder())
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
	for _, c := range bundle {
		fmt.Fprintln(&b, p.printCert(c))
	}
	return b.String(), nil
}

func (p TextBundlePrinter) printCert(cert *Cert) string {
	var b strings.Builder

	b.WriteString(box.Render(cert.Subject.CommonName))

	t := table.New().
		Border(lipgloss.Border{}).
		StyleFunc(func(_, _ int) lipgloss.Style {
			return cell
		})

	additional := buildAdditionalInfo(cert)

	t.Row("Subject", fmt.Sprintf(": %s%s", cert.Subject.CommonName, additional))
	t.Row("Issuer", fmt.Sprintf(": %s", cert.Issuer.CommonName))
	t.Row("Valid", fmt.Sprintf(": %v, expires in %v (%v)", cert.validity, cert.expiresIn, cert.NotAfter.Format("2006-02-01")))
	t.Row("Features", ": "+buildFeatures(cert))
	if len(cert.DNSNames) > 0 {
		t.Row("DNS SANs:", ": "+strings.Join(cert.DNSNames, "\n"))
	}

	b.WriteString(t.Render())
	return b.String()
}

func buildFeatures(cert *Cert) string {
	features := []string{}
	if cert.isRoot {
		features = append(features, "ROOT")
	}
	if cert.IsCA {
		features = append(features, "CA")
	}
	if len(cert.DNSNames) > 0 {
		features = append(features, "DNS SANs")
	}
	if len(cert.EmailAddresses) > 0 {
		features = append(features, "Email SANs")
	}
	if len(cert.IPAddresses) > 0 {
		features = append(features, "IP SANs")
	}
	if len(cert.URIs) > 0 {
		features = append(features, "URI SANs")
	}

	return strings.Join(features, ", ")
}

func buildAdditionalInfo(cert *Cert) string {
	info := []string{}
	if len(cert.DNSNames) > 0 {
		info = append(info, fmt.Sprintf("+%d DNS SANs", len(cert.DNSNames)))
	}
	if len(cert.EmailAddresses) > 0 {
		info = append(info, fmt.Sprintf("+%d Email SANs", len(cert.EmailAddresses)))
	}
	if len(cert.IPAddresses) > 0 {
		info = append(info, fmt.Sprintf("+%d IP SANs", len(cert.IPAddresses)))
	}
	if len(cert.URIs) > 0 {
		info = append(info, fmt.Sprintf("+%d URI SANs", len(cert.URIs)))
	}

	if len(info) == 0 {
		return ""
	}

	return fmt.Sprintf("(%v)", strings.Join(info, " "))
}
