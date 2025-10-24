package report

import "github.com/alexdzyoba/cert/certificate"

type Record struct {
	Cert   *certificate.Cert
	Error  error
	IsRoot bool
	IsCA   bool
}

type Report []*Record
