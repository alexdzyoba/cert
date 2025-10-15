package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

const PEMCertType = "CERTIFICATE"

// Cert wraps x509.Certificate for enhanced output
type Cert struct {
	*x509.Certificate
	fingerprint [32]byte
	isRoot      bool
	valid       bool
	verified    bool
	verifyErr   error
	validity    Duration
	expiresIn   Duration
}

func FromX509(cert *x509.Certificate) (*Cert, error) {
	return &Cert{
		Certificate: cert,
		validity:    validity(cert),
		expiresIn:   expiresIn(cert),
		fingerprint: sha256.Sum256(cert.Raw),
	}, nil
}

func FromBytes(bytes []byte) (*Cert, error) {
	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, errors.Wrap(err, "parse certificate")
	}

	return &Cert{
		Certificate: cert,
		validity:    validity(cert),
		expiresIn:   expiresIn(cert),
		fingerprint: sha256.Sum256(cert.Raw),
	}, nil
}

func FromPEM(data []byte) (*Cert, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate from PEM: empty PEM block")
	}
	return FromBytes(block.Bytes)
}

func validity(cert *x509.Certificate) Duration {
	return Duration(cert.NotAfter.Sub(cert.NotBefore))
}

func expiresIn(cert *x509.Certificate) Duration {
	return Duration(time.Until(cert.NotAfter))
}

// Bundle is an *ordered* list of certificates.
type Bundle []*Cert

func NewBundleFromCerts(certs []*x509.Certificate) (Bundle, error) {
	var b Bundle

	for _, c := range certs {
		cc, err := FromX509(c)
		if err != nil {
			return nil, err
		}
		b = append(b, cc)
	}
	return b, nil
}

func (cs Bundle) VerifySingle(asChain bool, t time.Time, roots *Roots) error {
	if roots == nil {
		return fmt.Errorf("roots not initialized")
	}

	intermediates := x509.NewCertPool()

	for _, c := range cs[1:] {
		intermediates.AddCert(c.Certificate)
	}

	chains, err := cs[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   t,
		Roots:         roots.CertPool,
	})
	if err != nil {
		log.Printf("VerifySingle error: %v", err)
	}

	// for _ chain := range chains {
	//
	// }

	spew.Config.MaxDepth = 3
	spew.Config.Indent = "    "
	// fmt.Printf("%#v\n", chains)
	spew.Dump(chains)

	// err = verifyChainPart(cs, t, roots)
	// if err == nil {
	// 	cs[i].verified = true
	// } else {
	// 	cs[i].verifyErr = err
	// }
	//
	// cs[i].isRoot = roots.Match(cs[i].fingerprint)
	// cs[i].valid = isValid(cs[i].Certificate, t)

	return nil
}

// Verify certificates in the bundle. Compared to builtin Verify method of
// crypto/x509 it verifies all chain parts, so if the leaf certificate is
// not valid, the rest will still be validated and shown.
func (cs Bundle) Verify(asChain bool, t time.Time, roots *Roots) error {
	var err error
	if roots == nil {
		return fmt.Errorf("roots not initialized")
	}

	// Verify every cert in the chain by iterating from the tail.
	var chains [][]*x509.Certificate
	printed := false
	for i := len(cs) - 1; i >= 0; i-- {
		if asChain {
			chains, err = verifyChainPart(cs[i:], t, roots)
		} else {
			err = verifyCert(cs[i], t, roots)
		}

		if err == nil {
			cs[i].verified = true
		} else {
			cs[i].verifyErr = err
		}

		cs[i].isRoot = roots.Match(cs[i].fingerprint)
		cs[i].valid = isValid(cs[i].Certificate, t)

		if !printed {
			printed = true
			printer := NewTextBundlePrinter()
			for j, chain := range chains {
				fmt.Printf("chain %d of %d/%d\n", j, i, len(cs))
				b, err := NewBundleFromCerts(chain)
				if err != nil {
					log.Println(err)
					continue
				}
				s, _ := printer.Print(b, roots)
				fmt.Println(s)
			}
		}
	}
	return nil
}

// verifyChainPart verifies the first certificate in the chain using other certs
// as intermediates.
func verifyChainPart(chain []*Cert, t time.Time, roots *Roots) ([][]*x509.Certificate, error) {
	intermediates := x509.NewCertPool()

	for _, c := range chain[1:] {
		intermediates.AddCert(c.Certificate)
	}

	return chain[0].Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   t,
		Roots:         roots.CertPool,
	})
}

// verifyCert simply verifies the cert using roots without trying to build any
// chain.
func verifyCert(cert *Cert, t time.Time, roots *Roots) error {
	_, err := cert.Verify(x509.VerifyOptions{
		CurrentTime: t,
		Roots:       roots.CertPool,
	})
	return err
}

func isValid(cert *x509.Certificate, t time.Time) bool {
	return t.After(cert.NotBefore) && t.Before(cert.NotAfter)
}
