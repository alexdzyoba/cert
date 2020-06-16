package main

import (
	"flag"
	"io/ioutil"
	"log"
	"time"

	"github.com/alexdzyoba/cert/dump"
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

	p := dump.Printer{NoChain: *noChain, Time: t}
	p.Dump(data)
}
