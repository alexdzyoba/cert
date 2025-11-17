package main

import "fmt"

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

type FormatOptions struct {
	Verbosity  OutputLevel
	AppendRoot bool
}
