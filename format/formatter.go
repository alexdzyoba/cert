package format

import "github.com/alexdzyoba/cert/verify"

type Formatter interface {
	Format(*verify.Report) string
}

// TODO: map of supported formats?
// TODO: factory of formatters?
