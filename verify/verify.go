package verify

import (
	"time"

	"github.com/alexdzyoba/cert/certificate"
)

type Record struct {
	Cert   *certificate.Cert
	Error  error
	IsRoot bool
	IsCA   bool
}

type Report []*Record

type Options struct {
	Time      time.Time
	RootsPath string
}

func Verify(bundle *certificate.Bundle, opts *Options) (*Report, error) {
	return nil, nil
}
