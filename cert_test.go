package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/andreyvit/diff"
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

var update = flag.Bool("update", false, "update golden files")

func TestCertString(t *testing.T) {
	testFiles := []string{
		"addtrust.crt",
		"letsencrypt-fullchain.pem",
	}

	// Set timezone to fixate serialization of datetime
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal(err)
	}
	time.Local = loc

	for _, f := range testFiles {
		filename := filepath.Join("testdata", f)
		golden := filepath.Join("testdata", f+".golden")

		certs, err := load(filename)
		if err != nil {
			t.Fatal(err)
		}

		got := certs.String()

		if *update {
			ioutil.WriteFile(golden, []byte(got), 0644)
		}

		wantBytes, err := ioutil.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		want := string(wantBytes)

		if got != want {
			t.Errorf("%s serialization doesn't match golden file %s:\n%v", filename, golden, diff.LineDiff(want, got))
		}
	}
}
