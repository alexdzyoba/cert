package main

import (
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
		f.formatRecord(w, record)
	}

	if err := w.Flush(); err != nil {
		return "", fmt.Errorf("tabwriter failed: %w", err)
	}

	return s.String(), nil
}

func (f *TextFormatter) formatRecord(w *tabwriter.Writer, record *Record) {
	fmt.Fprintf(w, "Subject:\t%s\n", record.Cert.inner.Subject.String())
	fmt.Fprintf(w, "Issuer:\t%s\n", record.Cert.inner.Issuer.String())
	fmt.Fprintf(w, "Fingerprint:\t%X\n", record.Cert.fingerprint)
	fmt.Fprintf(w, "Is Root:\t%v\n", record.IsRoot)

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
	if rec.ExpiresIn < 0 {
		return fmt.Sprintf("%v, expired on %v %s", rec.Validity, rec.Cert.inner.NotAfter.Format("2006-01-02"), printBool(rec.Valid))
	}
	return fmt.Sprintf("%v, expires in %v (%v) %s", rec.Validity, rec.ExpiresIn, rec.Cert.inner.NotAfter.Format("2006-01-02"), printBool(rec.Valid))
}

func printBool(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
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
