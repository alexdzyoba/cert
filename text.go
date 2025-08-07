package main

import (
	"crypto/x509/pkix"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/list"
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

const DefaultListLimit = 5

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

	t.Row("Subject", ": "+p.formatSubject(cert))
	t.Row("Issuer", ": "+p.formatName(cert.Issuer))
	t.Row("Valid", ": "+p.formatValidity(cert))
	t.Row("Features", ": "+p.buildFeatures(cert))
	b.WriteString(t.Render())
	if len(cert.DNSNames) > 0 {
		b.WriteString(cell.Render("\nDNS SANs:\n" + p.formatList(cert.DNSNames)))
	}

	return b.String()
}

func (p TextBundlePrinter) formatValidity(cert *Cert) string {
	if cert.expiresIn < 0 {
		return fmt.Sprintf("%v, expired on %v", cert.validity, cert.NotAfter.Format("2006-02-01"))
	}
	return fmt.Sprintf("%v, expires in %v (%v)", cert.validity, cert.expiresIn, cert.NotAfter.Format("2006-02-01"))
}

func (p TextBundlePrinter) buildFeatures(cert *Cert) string {
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

func (p TextBundlePrinter) formatSubject(cert *Cert) string {
	if p.level > BaseLevel {
		return cert.Subject.String()
	}

	subject := p.formatName(cert.Subject)

	sans := []string{}
	if len(cert.DNSNames) > 0 {
		sans = append(sans, fmt.Sprintf("+%d DNS SANs", len(cert.DNSNames)))
	}
	if len(cert.EmailAddresses) > 0 {
		sans = append(sans, fmt.Sprintf("+%d Email SANs", len(cert.EmailAddresses)))
	}
	if len(cert.IPAddresses) > 0 {
		sans = append(sans, fmt.Sprintf("+%d IP SANs", len(cert.IPAddresses)))
	}
	if len(cert.URIs) > 0 {
		sans = append(sans, fmt.Sprintf("+%d URI SANs", len(cert.URIs)))
	}

	if len(sans) == 0 {
		return subject
	}

	return fmt.Sprintf("%s (%v)", subject, strings.Join(sans, " "))
}

func (p TextBundlePrinter) formatName(name pkix.Name) string {
	if p.level > BaseLevel {
		return name.String()
	}

	s := []string{name.CommonName}
	if len(name.OrganizationalUnit) > 0 {
		s = append(s, name.OrganizationalUnit...)
	}
	if len(name.Organization) > 0 {
		s = append(s, name.Organization...)
	}
	if len(name.Country) > 0 {
		s = append(s, name.Country...)
	}

	return strings.Join(s, ", ")
}

func (p TextBundlePrinter) formatList(ss []string) string {
	items := ss
	limit := int(math.MaxInt32)
	if p.level < VerboseLevel {
		limit = DefaultListLimit
	}

	if len(ss) > limit {
		items = ss[:limit]
	}
	more := len(ss) - limit

	l := list.New(items).Enumerator(list.Dash)
	if more > 0 {
		l.Item(fmt.Sprintf("(... %d more)", more))
	}

	return l.String()
}
