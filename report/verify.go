package report

import (
	"time"

	"github.com/alexdzyoba/cert/certificate"
)

type VerifyOptions struct {
	Time      time.Time
	RootsPath string
}

func Verify(bundle *certificate.Bundle, opts *VerifyOptions) (*Report, error) {
	return nil, nil
}
