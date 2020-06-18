package main

import (
	"flag"
	"io/ioutil"
	"log"
	"time"

	"github.com/alexdzyoba/cert/certificate"
	"github.com/alexdzyoba/cert/dump"
	"github.com/alexdzyoba/cert/parser"
)

func main() {
	filename := flag.String("f", "", "filename")
	timeString := flag.String("t", "", "date and time in RFC3339 format")
	noChain := flag.Bool("nochain", false, "disable chain validation")
	flag.Parse()

	data, err := ioutil.ReadFile(*filename)
	if err != nil {
		log.Fatal(err)
	}

	t := time.Now()
	if *timeString != "" {
		t, err = time.Parse(time.RFC3339, *timeString)
		if err != nil {
			log.Fatal(err)
		}
	}

	// parse
	entities, err := parser.Parse(data)
	if err != nil {
		log.Fatal("failed to parse input data: ", err)
	}

	if len(entities) > 1 && !*noChain {
		verifyChain(entities, t)
	}

	// dump
	p := dump.Printer{NoChain: *noChain}
	p.Dump(entities)
}

func verifyChain(entities []*parser.Entity, t time.Time) {
	var certs []*certificate.Cert

	for _, e := range entities {
		cert, ok := e.Val.(*certificate.Cert)
		if ok {
			certs = append(certs, cert)
		}
	}

	certificate.VerifyChain(certs, t)
}
