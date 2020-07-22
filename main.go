package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	var (
		timeString string
		noChain    bool
		verbose    bool
	)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] <file or URL>\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "\nOptions:\n")
		flag.PrintDefaults()
	}

	flag.StringVar(&timeString, "time", "", "date and time in RFC3339 format")
	flag.BoolVar(&noChain, "nochain", false, "disable chain validation")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.Parse()

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}

	var err error

	// Override time from flag
	t := time.Now()
	if timeString != "" {
		t, err = time.Parse(time.RFC3339, timeString)
		if err != nil {
			log.Fatal(err)
		}
	}

	resource := flag.Args()[0]

	certs, err := load(resource)
	if err != nil {
		log.Fatal(err)
	}

	// Verify cert chain by default
	if len(certs) > 1 && !noChain {
		chain := NewChain(certs, t, verbose)
		fmt.Println(chain)
	} else {
		fmt.Println(certs)
	}
}
