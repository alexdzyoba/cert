package certificate

import (
	"crypto/x509"
	"log"
	"time"

	"github.com/pkg/errors"
)

func VerifyChain(chain []*Cert, t time.Time) {
	for i := len(chain) - 1; i >= 0; i-- {
		err := verifyChainPart(chain[i:], t)
		if err == nil {
			chain[i].verified = true
		} else {
			log.Printf("failed to verify chain part at %s: %v", chain[i].Subject, err)
		}
	}
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
