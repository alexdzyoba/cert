package main

import (
	"encoding/pem"
	"fmt"
	"iter"
	"strings"
)

const PEMCertType = "CERTIFICATE"

type PEMParser struct {
	data []byte
}

func NewPEMParser(data []byte) *PEMParser {
	return &PEMParser{data}
}

// Blocks returns iterator that yields parsed certificate blocks in DER format
func (p *PEMParser) Blocks() iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		for block, rest := pem.Decode(p.data); block != nil; block, rest = pem.Decode(rest) {
			if block.Type == PEMCertType {
				if !yield(block.Bytes) {
					return
				}
			}
		}
	}
}

func PEMFormat(bundle *Bundle) (string, error) {
	var b strings.Builder
	for _, cert := range *bundle {
		err := pem.Encode(&b, &pem.Block{
			Type:  PEMCertType,
			Bytes: cert.raw.Raw,
		})
		if err != nil {
			return "", fmt.Errorf("encoding to PEM: %w", err)
		}
	}
	return b.String(), nil
}
