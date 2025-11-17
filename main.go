package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/araddon/dateparse"
	"github.com/spf13/pflag"
)

func main() {
	config, err := ParseArguments()
	if err != nil {
		log.Printf("failed to parse arguments: %v", err)
		pflag.Usage()
		os.Exit(1)
	}

	bundle, err := Load(config.Source)
	if err != nil {
		log.Fatalf("failed to load from %v: %v", config.Source, err)
	}

	report, err := Verify(bundle, &VerifyOptions{
		Time:      config.Time,
		RootsPath: config.RootsPath,
	})
	if err != nil {
		log.Fatalf("failed to verify: %v", err)
	}

	Print(report, config)
}

func Print(report *Report, config *Config) {
	var f Formatter

	switch config.Format {
	case FormatPEM:
		f = &PEMFormatter{}
	case FormatText:
		f = &TextFormatter{
			Verbosity:  config.Verbosity,
			AppendRoot: config.AppendRoot,
		}
	default:
		log.Fatalf("unsupported format %v", config.Format)
	}

	output, err := f.Format(report)
	if err != nil {
		log.Fatalf("formatting: %v", err)
	}

	fmt.Println(output)
}

func ParseArguments() (*Config, error) {
	pflag.Usage = func() {
		fmt.Fprintf(pflag.CommandLine.Output(), "Usage: %s [options] <file or URL>\n", os.Args[0])
		fmt.Fprintf(pflag.CommandLine.Output(), "\nOptions:\n")
		pflag.PrintDefaults()
	}

	format := FormatP("format", "f", "text", "Output format - text, pem.")
	timeFlag := pflag.StringP("time", "t", "", "Override date and time for validation.")
	verbosityFlag := pflag.CountP("verbose", "v", "Increase output verbosity. Can be specified multiple times.")
	rootsFlag := pflag.StringP("roots", "r", "", "Path to custom roots bundle.")
	appendRootFlag := pflag.BoolP("with-root", "R", false, "Print root certificate used during verification.")
	pflag.Parse()

	// Validate exactly one positional argument
	args := pflag.Args()
	if len(args) == 0 {
		return nil, fmt.Errorf("missing required argument: <file or URL>")
	}
	if len(args) > 1 {
		return nil, fmt.Errorf("too many arguments: expected 1, got %d", len(args))
	}

	source := args[0]

	// Use current time by default
	t := time.Now()
	if *timeFlag != "" {
		var err error
		t, err = dateparse.ParseAny(*timeFlag)
		if err != nil {
			return nil, fmt.Errorf("time parsing: %w", err)
		}
	}

	// Parse output level
	outputLevel, err := NewOutputLevel(*verbosityFlag)
	if err != nil {
		return nil, err
	}

	return &Config{
		Source:     source,
		Format:     *format,
		Time:       t,
		Verbosity:  outputLevel,
		RootsPath:  *rootsFlag,
		AppendRoot: *appendRootFlag,
	}, nil
}
