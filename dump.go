package main

import (
	"fmt"
)

func Dump(certs []*Cert, noChain bool) {
	level := "  "
	for i, c := range certs {
		fmt.Printf("[%d] Certificate:\n", i)
		fmt.Printf("%s\n", c.Indent(level))
		if !noChain {
			level += "  "
		}
	}
}
