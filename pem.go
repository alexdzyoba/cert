package main

import (
	"encoding/pem"
	"fmt"
	"iter"
	"strings"
)

const PEMCertType = "CERTIFICATE"

// PEMBlocks returns iterator that yields parsed certificate blocks in DER format
func PEMBlocks(data []byte) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
			if block.Type == PEMCertType {
				if !yield(block.Bytes) {
					return
				}
			}
		}
	}
}

type PEMFormatter struct{}

func (f *PEMFormatter) Format(report Report) (string, error) {
	var b strings.Builder
	for _, rec := range report {
		cert := rec.Cert
		err := pem.Encode(&b, &pem.Block{
			Type:  PEMCertType,
			Bytes: cert.Bytes(),
		})
		if err != nil {
			return "", fmt.Errorf("encoding to PEM: %w", err)
		}
	}
	return b.String(), nil
}
