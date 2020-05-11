package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// Indenter is an interface that wraps Indent method that returns type in a
// simple indented format
type Indenter interface {
	Indent(indent string) string
}

// Cert wraps x509.Certificate for enhanced output
type Cert struct {
	x509.Certificate
}

func NewCertFromX509Cert(cert *x509.Certificate) *Cert {
	return &Cert{*cert}
}

func (c *Cert) Indent(indent string) string {
	var b strings.Builder

	fmt.Fprintf(&b, indent+"issuer: %s\n", c.Issuer)
	fmt.Fprintf(&b, indent+"subject: %s\n", c.Subject)

	format := "2006-01-02 15:04:05"
	fmt.Fprintf(&b, indent+"valid: from '%v' to '%v'\n",
		c.NotBefore.Local().Format(format),
		c.NotAfter.Local().Format(format),
	)

	return b.String()
}

func main() {
	filename := os.Args[1]

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	// Parse every PEM block and print it
	blockIndex := 0
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "PUBLIC KEY":
			pubkey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("Public key of type %T, %v\n", pubkey, pubkey)
			blockIndex++
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Println(err)
			}

			Print(blockIndex, block.Type, NewCertFromX509Cert(cert))
			blockIndex++
		default:
			log.Printf("skipping unknown type %s\n", block.Type)
		}
	}
}

func Print(i int, typ string, str Indenter) {
	fmt.Printf("[%d] %s:\n", i, typ)
	fmt.Printf("%s\n", str.Indent("  "))
}
