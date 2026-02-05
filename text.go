package main

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"
)

type TextFormatter struct {
	Verbosity OutputLevel
}

func (f *TextFormatter) Format(report Report) (string, error) {
	var s strings.Builder
	w := tabwriter.NewWriter(&s, 0, 0, 1, ' ', 0)
	for _, record := range report {
		// Flush tabwriter before writing header directly to s,
		// so the header line isn't mangled by tab alignment.
		if err := w.Flush(); err != nil {
			return "", fmt.Errorf("tabwriter failed: %w", err)
		}
		f.formatHeader(&s, record)
		f.formatFields(w, record)
	}

	if err := w.Flush(); err != nil {
		return "", fmt.Errorf("tabwriter failed: %w", err)
	}

	return s.String(), nil
}

const (
	headerWidth = 80
	ansiGreen   = "\033[32m"
	ansiRed     = "\033[31m"
	ansiReset   = "\033[0m"
)

func (f *TextFormatter) formatHeader(s *strings.Builder, record *Record) {
	cn := record.Cert.inner.Subject.CommonName
	if cn == "" {
		cn = record.Cert.inner.Subject.String()
	}

	status := printBool(record.Error == nil)
	prefix := fmt.Sprintf("--- %s %s ", status, cn)
	pad := max(headerWidth-len(prefix), 3)
	fmt.Fprintf(s, "%s%s\n", prefix, strings.Repeat("-", pad))
}

func (f *TextFormatter) formatFields(w *tabwriter.Writer, record *Record) {
	fmt.Fprintf(w, "Subject:\t%s\n", f.formatName(record.Cert.inner.Subject))
	fmt.Fprintf(w, "Issuer:\t%s\n", f.formatName(record.Cert.inner.Issuer))
	if f.Verbosity >= VerboseOutput {
		fmt.Fprintf(w, "Fingerprint:\t%X\n", record.Cert.fingerprint)
	}

	if record.Error != nil {
		fmt.Fprintf(w, "Error:\t%v\n", record.Error)
	}

	if f.Verbosity >= VerboseOutput {
		fmt.Fprintf(w, "Not Before:\t%s\n", record.Cert.inner.NotBefore.String())
		fmt.Fprintf(w, "Not After:\t%s\n", record.Cert.inner.NotAfter.String())
	} else {
		fmt.Fprintf(w, "Valid:\t%s\n", f.formatValidity(record))
	}

	fmt.Fprintf(w, "\n")
}

func (f *TextFormatter) formatValidity(rec *Record) string {
	inner := rec.Cert.inner
	if rec.ExpiresIn < 0 {
		return fmt.Sprintf("%v, expired on %v %s", rec.Validity, inner.NotAfter.Format("2006-01-02"), printBool(rec.Valid))
	}
	return fmt.Sprintf("%v, expires in %v (%v) %s", rec.Validity, rec.ExpiresIn, inner.NotAfter.Format("2006-01-02"), printBool(rec.Valid))
}

func (f *TextFormatter) formatName(name pkix.Name) string {
	if f.Verbosity >= VerboseOutput {
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

func printBool(b bool) string {
	if b {
		return ansiGreen + "[OK]" + ansiReset
	}
	return ansiRed + "[ERR]" + ansiReset
}

// Duration provides custom time.Duration string serialization
type Duration time.Duration

func (d Duration) String() string {
	const (
		day   = 24
		week  = 7 * day
		month = 30 * day
		year  = 365 * day
	)

	h := time.Duration(d).Hours()
	switch {
	case h >= year:
		return fmt.Sprintf("%.1f years", h/year)
	case h >= month:
		return fmt.Sprintf("%.1f months", h/month)
	case h >= week:
		return fmt.Sprintf("%.1f weeks", h/week)
	case h >= day:
		return fmt.Sprintf("%.1f days", h/day)
	default:
		return time.Duration(d).String()
	}
}
