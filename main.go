package main

import (
	"flag"
	"log"
	"os"
	"time"
)

func main() {
	timeString := flag.String("time", "", "date and time in RFC3339 format")
	noChain := flag.Bool("nochain", false, "disable chain validation")
	flag.Parse()

	var err error

	// Load time
	t := time.Now()
	if *timeString != "" {
		t, err = time.Parse(time.RFC3339, *timeString)
		if err != nil {
			log.Fatal(err)
		}
	}

	resource := flag.Args()[0]

	var certs []*Cert

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
	if len(certs) > 1 && !*noChain {
		VerifyChain(certs, t)
	}

	Dump(certs, *noChain)
}
