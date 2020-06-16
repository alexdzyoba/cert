package dump

import (
	"fmt"
	"log"

	"github.com/alexdzyoba/cert/certificate"
)

// Formatter describe type that can be formatted for output
type Formatter interface {
	// Name returns type name
	Name() string

	// Indent returns type in a simple indented format
	Indent(intent string) string
}

func Print(i int, val Formatter) {
	fmt.Printf("[%d] %s:\n", i, val.Name())
	fmt.Printf("%s\n", val.Indent("  "))
}

func PrintChain(chain []*certificate.Cert) {
	log.Println("printing chain")

	level := "  "
	for i, c := range chain {
		fmt.Printf("[%d] %s:\n", i, c.Name())
		fmt.Printf("%s\n", c.Indent(level))
		level += "  "
	}
}
