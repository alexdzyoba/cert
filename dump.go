package main

import (
	"encoding/pem"
	"fmt"
	"log"

	"github.com/alexdzyoba/cert/certificate"
	"github.com/alexdzyoba/cert/pubkey"
)

// Formatter describe type that can be formatted for output
type Formatter interface {
	// Name returns type name
	Name() string

	// Indent returns type in a simple indented format
	Indent(intent string) string
}

func dump(data []byte) {
	// Parse every PEM block and print it
	blockIndex := 0
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "PUBLIC KEY":
			pub, err := pubkey.New(block.Bytes)
			if err != nil {
				log.Println(err)
			}

			Print(blockIndex, pub)
			blockIndex++

		case "CERTIFICATE":
			crt, err := certificate.New(block.Bytes)
			if err != nil {
				log.Println(err)
			}

			Print(blockIndex, crt)
			blockIndex++
		default:
			log.Printf("skipping unknown type %s\n", block.Type)
		}
	}
}

func Print(i int, val Formatter) {
	fmt.Printf("[%d] %s:\n", i, val.Name())
	fmt.Printf("%s\n", val.Indent("  "))
}
