package main

import (
	"os"
	"testing"
)

func TestMatchRoots(t *testing.T) {
	roots := loadRoots(t)

	certPEM, err := os.ReadFile("testdata/addtrust.crt")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := FromPEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	if !roots.Match(cert.fingerprint) {
		t.Errorf("cert is not matched as root")
	}
}
