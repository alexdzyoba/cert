package main

import (
	"encoding/pem"
	"fmt"
	"strings"
)

type PEMBundlePrinter struct{}

func (p PEMBundlePrinter) Print(bundle Bundle) (string, error) {
	var s strings.Builder

	for _, cert := range bundle {
		err := pem.Encode(&s, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return "", fmt.Errorf("cannot encode cert %v: %w", cert.Subject, err)
		}
	}

	return s.String(), nil
}
