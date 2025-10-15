package main

import (
	"crypto/x509"
	"time"
)

// VerifyOptions configures certificate chain verification.
type VerifyOptions struct {
	Time          time.Time
	Roots         Bundle
	Intermediates Bundle
}

// Verify validates a certificate bundle and returns a report with results for each certificate.
func Verify(bundle Bundle, opts *VerifyOptions) (Report, error) {
	records := make([]*Record, 0, len(bundle))

	// Start verify with the full chain, skipping invalid certificates starting
	// from leaf.
	var s int // start of the valid chain
	for s = 0; s < len(bundle); s++ {
		_, err := verifyChain(bundle[s:], opts)
		if err != nil {
			records = append(records, NewRecord(bundle[s], err, opts))
			// Continue with the smaller chain
		} else {
			break
		}
	}

	// Create records for the verified chain (if any)
	for i := s; i < len(bundle); i++ {
		records = append(records, NewRecord(bundle[i], nil, opts))
	}

	return Report(records), nil
}

// verifyChain verifies the first certificate in the chain using other certs
// as intermediates.
func verifyChain(chain []*Certificate, opts *VerifyOptions) ([][]*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, nil
	}

	intermediates := x509.NewCertPool()

	if len(chain) > 1 {
		for _, c := range chain[1:] {
			intermediates.AddCert(c.inner)
		}
	}

	for _, c := range opts.Intermediates {
		intermediates.AddCert(c.inner)
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	for _, c := range opts.Roots {
		roots.AddCert(c.inner)
	}

	return chain[0].inner.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   opts.Time,
	})
}
