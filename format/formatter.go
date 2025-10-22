package format

import "github.com/alexdzyoba/cert/certificate"

type Formatter interface {
	Format(*certificate.Bundle) string
}

// TODO: map of supported formats?
// TODO: factory of formatters?
