package dump

import (
	"encoding/pem"
	"log"
	"time"

	"github.com/alexdzyoba/cert/certificate"
	"github.com/alexdzyoba/cert/pubkey"
)

type Printer struct {
	NoChain bool
	Time    time.Time

	chain []*certificate.Cert
}

func (p *Printer) Dump(data []byte) {
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
				log.Println("certificate dump error: ", err)
			}

			if p.NoChain {
				Print(blockIndex, crt)
				blockIndex++
			} else {
				p.chain = append(p.chain, crt)
			}
		default:
			log.Printf("skipping unknown type %s\n", block.Type)
		}
	}

	if !p.NoChain {
		err := certificate.VerifyChain(p.chain, p.Time)
		if err != nil {
			log.Println("chain verify error: ", err)
		}

		PrintChain(p.chain)
	}
}
