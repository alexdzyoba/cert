package main

import (
	"errors"
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

	flag.StringVar(&timeString, "time", "", "date and time in RFC3339 format")
	flag.BoolVar(&noChain, "nochain", false, "disable chain validation")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.Parse()

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

	var certs Certs

	// Decide where to load certs from
	f, err := os.Open(resource)
	if errors.Is(err, os.ErrNotExist) {
		certs, err = fromURL(resource)
	} else {
		certs, err = fromReader(f)
	}
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
