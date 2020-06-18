package dump

import (
	"fmt"

	"github.com/alexdzyoba/cert/parser"
)

type Printer struct {
	NoChain bool
}

func (p *Printer) Dump(entities []*parser.Entity) {
	level := "  "
	for i, e := range entities {
		v, ok := e.Val.(Formatter)
		if !ok {
			// log.Printf("cannot dump value of type %v", e.Type)
			continue
		}

		fmt.Printf("[%d] %s:\n", i, v.Name())
		fmt.Printf("%s\n", v.Indent(level))
		if !p.NoChain {
			level += "  "
		}
	}
}

// Formatter describe type that can be formatted for output
type Formatter interface {
	// Name returns type name
	Name() string

	// Indent returns type in a simple indented format
	Indent(intent string) string
}
