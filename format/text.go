package format

import "github.com/alexdzyoba/cert/certificate"

type TextFormatter struct {
	opts *TextFormatterOptions
}

type TextFormatterOptions struct {
	Verbosity  OutputLevel
	AppendRoot bool
}

func NewTextFormatter(opts *TextFormatterOptions) *TextFormatter {
	return &TextFormatter{opts}
}

func (tf *TextFormatter) Format(bundle *certificate.Bundle) string {
	return ""
}
