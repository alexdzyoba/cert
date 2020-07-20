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
		noVerify   bool
	)

	flag.StringVar(&timeString, "time", "", "date and time in RFC3339 format")
	flag.BoolVar(&noVerify, "noverify", false, "disable chain validation")
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
	_, err = os.Stat(resource)
	if os.IsNotExist(err) {
		certs, err = fromURL(resource)
	} else {
		certs, err = fromFile(resource)
	}
	if err != nil {
		log.Fatal(err)
	}

	// Verify cert chain by default
	if len(certs) > 1 && !noVerify {
		chain := NewChain(certs, t)
		fmt.Println(chain)
	} else {
		fmt.Println(certs)
	}
}
