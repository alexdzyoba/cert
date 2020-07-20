package main

import (
	"encoding/pem"

	"github.com/pkg/errors"
)

func Parse(data []byte) ([]*Cert, error) {
	certs := make([]*Cert, 0)
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == "CERTIFICATE" {
			cert, err := FromBytes(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "parsing certificate")
			}

			certs = append(certs, cert)
		}
	}

	return certs, nil
}
