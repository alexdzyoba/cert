package main

import (
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

type OutputLevel int

const (
	CompactOutput OutputLevel = iota
	VerboseOutput
	FullOutput
)

func NewOutputLevel(n int) (OutputLevel, error) {
	if n < int(CompactOutput) || n > int(FullOutput) {
		return 0, fmt.Errorf("cannot parse output level from value %d", n)
	}

	return OutputLevel(n), nil
}

type Format string

const (
	FormatText Format = "text"
	FormatPEM  Format = "pem"
)

var validFormats = []Format{FormatText, FormatPEM}

// ParseFormat validates input and converts to a Format
func ParseFormat(s string) (Format, error) {
	f := Format(strings.ToLower(s))
	for _, v := range validFormats {
		if f == v {
			return f, nil
		}
	}
	return "", fmt.Errorf("invalid format %q (valid: %v)", s, validFormats)
}

// FormatValue implements pflag.Value
type FormatValue struct {
	Value *Format
}

func (f *FormatValue) String() string {
	if f.Value == nil {
		return ""
	}
	return string(*f.Value)
}

func (f *FormatValue) Set(s string) error {
	v, err := ParseFormat(s)
	if err != nil {
		return err
	}
	*f.Value = v
	return nil
}

func (f *FormatValue) Type() string {
	return "format"
}

// FormatP creates a new Format flag and returns its value
func FormatP(name, shorthand string, value Format, usage string) *Format {
	p := new(Format)
	*p = value
	pflag.CommandLine.VarP(&FormatValue{Value: p}, name, shorthand,
		fmt.Sprintf("%s (valid: %v)", usage, validFormats))
	return p
}
