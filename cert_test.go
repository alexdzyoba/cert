package main

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

func TestMatchRoots(t *testing.T) {
	roots := x509.NewCertPool()

	rootsPEM, err := ioutil.ReadFile("testdata/ca-bundle.crt")
	if err != nil {
		t.Fatal(err)
	}

	if !roots.AppendCertsFromPEM(rootsPEM) {
		t.Fatal(err)
	}

	certPEM, err := ioutil.ReadFile("testdata/addtrust.crt")
	if err != nil {
		t.Fatal(err)
	}

	certData, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certData.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if !matchRoots(cert, roots) {
		t.Errorf("cert is not matched as root")
	}
}
