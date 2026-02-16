package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	headerWidth = 80
	ansiBold    = "\033[1m"
	ansiGreen   = "\033[32m"
	ansiRed     = "\033[31m"
	ansiReset   = "\033[0m"

	maxCompactSANs = 3
	maxVerboseSANs = 20
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

func (f *TextFormatter) formatHeader(s *strings.Builder, record *Record) {
	cn := record.Cert.inner.Subject.CommonName
	if cn == "" {
		cn = record.Cert.inner.Subject.String()
	}

	status := printBool(record.Error == nil)
	prefix := fmt.Sprintf("--- %s%s%s %s ", ansiBold, cn, ansiReset, status)
	pad := max(headerWidth-len(prefix), 3)
	fmt.Fprintf(s, "%s%s\n", prefix, strings.Repeat("-", pad))
}

func (f *TextFormatter) formatFields(w *tabwriter.Writer, record *Record) {
	cert := record.Cert.inner

	fmt.Fprintf(w, "Subject:\t%s\n", f.formatName(cert.Subject))
	if sans := f.formatSANs(cert); sans != "" {
		fmt.Fprintf(w, "SANs:\t%s\n", sans)
	}

	fmt.Fprintf(w, "Issuer:\t%s\n", f.formatName(cert.Issuer))

	if record.Error != nil {
		fmt.Fprintf(w, "Error:\t%v\n", record.Error)
	}

	if f.Verbosity >= VerboseOutput {
		fmt.Fprintf(w, "Not Before:\t%s %s\n", cert.NotBefore.String(), printBool(record.Validity.NotBeforeOK))
		fmt.Fprintf(w, "Not After:\t%s %s\n", cert.NotAfter.String(), printBool(record.Validity.NotAfterOK))
	} else {
		fmt.Fprintf(w, "Valid:\t%s\n", f.formatValidity(record))
	}

	if f.Verbosity >= VerboseOutput {
		fmt.Fprintf(w, "Fingerprint:\t%X\n", record.Cert.fingerprint)
		fmt.Fprintf(w, "Key:\t%s\n", formatKeyInfo(cert))
		fmt.Fprintf(w, "Signature:\t%s\n", cert.SignatureAlgorithm)
	}

	if f.Verbosity >= FullOutput {
		if ku := formatKeyUsage(cert.KeyUsage); ku != "" {
			fmt.Fprintf(w, "Key Usage:\t%s\n", ku)
		}
		if eku := formatExtKeyUsage(cert.ExtKeyUsage); eku != "" {
			fmt.Fprintf(w, "Ext Key Usage:\t%s\n", eku)
		}
	}

	fmt.Fprintf(w, "\n")
}

func (f *TextFormatter) formatSANs(cert *x509.Certificate) string {
	sans := f.collectSANs(cert)

	if len(sans) == 0 {
		return ""
	}

	var maxSANs int
	switch f.Verbosity {
	case FullOutput:
		maxSANs = len(sans)
	case VerboseOutput:
		maxSANs = maxVerboseSANs
	default:
		maxSANs = maxCompactSANs
	}

	n := min(len(sans), maxSANs)
	s := strings.Join(sans[:n], ", ")
	if extra := len(sans) - n; extra > 0 {
		s += fmt.Sprintf(" (+%d more)", extra)
	}

	return s
}

func (f *TextFormatter) collectSANs(cert *x509.Certificate) []string {
	if f.Verbosity == CompactOutput {
		return cert.DNSNames
	}

	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, "DNS:"+dns)
	}

	for _, ip := range cert.IPAddresses {
		sans = append(sans, "IP:"+ip.String())
	}

	for _, email := range cert.EmailAddresses {
		sans = append(sans, "Email:"+email)
	}

	for _, uri := range cert.URIs {
		sans = append(sans, "URI:"+uri.String())
	}

	return sans
}

func formatKeyInfo(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d bits", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ECDSA %s", pub.Curve.Params().Name)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", pub)
	}
}

var keyUsageNames = [...]struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Certificate Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

func formatKeyUsage(ku x509.KeyUsage) string {
	var names []string
	for _, entry := range keyUsageNames {
		if ku&entry.bit != 0 {
			names = append(names, entry.name)
		}
	}
	return strings.Join(names, ", ")
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "Server Authentication",
	x509.ExtKeyUsageClientAuth:                 "Client Authentication",
	x509.ExtKeyUsageCodeSigning:                "Code Signing",
	x509.ExtKeyUsageEmailProtection:            "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSEC End System",
	x509.ExtKeyUsageIPSECTunnel:                "IPSEC Tunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSEC User",
	x509.ExtKeyUsageTimeStamping:               "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape Server Gated Crypto",
}

func formatExtKeyUsage(eku []x509.ExtKeyUsage) string {
	var names []string
	for _, usage := range eku {
		if name, ok := extKeyUsageNames[usage]; ok {
			names = append(names, name)
		} else {
			names = append(names, fmt.Sprintf("Unknown(%d)", usage))
		}
	}
	return strings.Join(names, ", ")
}

func (f *TextFormatter) formatValidity(rec *Record) string {
	v := rec.Validity
	inner := rec.Cert.inner

	if v.ExpiresIn < 0 {
		return fmt.Sprintf("%v, expired on %v %s", v.Period, inner.NotAfter.Format("2006-01-02"), printBool(v.OK))
	}

	return fmt.Sprintf("%v, expires in %v (%v) %s", v.Period, v.ExpiresIn, inner.NotAfter.Format("2006-01-02"), printBool(v.OK))
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
