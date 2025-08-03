package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andreyvit/diff"
	"github.com/fatih/color"
)

var update = flag.Bool("update", false, "update golden files")

func TestMatchRoots(t *testing.T) {
	roots := loadRoots(t)

	certPEM, err := os.ReadFile("testdata/addtrust.crt")
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

func TestCertString(t *testing.T) {
	tests := []struct {
		f string
		t time.Time
	}{
		{"addtrust.crt", time.Date(2010, 10, 10, 11, 11, 11, 0, time.UTC)},
	}

	// Set timezone to fixate serialization of datetime
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal(err)
	}
	time.Local = loc

	roots := loadRoots(t)

	for _, tt := range tests {
		filename := filepath.Join("testdata", tt.f)
		golden := filepath.Join("testdata", tt.f+".golden")

		certs, err := load(filename)
		if err != nil {
			t.Fatal(err)
		}
		certs.Verify(false, tt.t, roots)

		got := certs.String()

		if *update {
			os.WriteFile(golden, []byte(got), 0644)
		}

		wantBytes, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		want := string(wantBytes)

		if got != want {
			t.Errorf("%s serialization doesn't match golden file %s:\n%v", filename, golden, diff.LineDiff(want, got))
		}
	}
}

func TestChainString(t *testing.T) {
	testCases := []struct {
		filename string
		t        time.Time
	}{
		{"google.crt", time.Date(2025, 8, 3, 18, 57, 0, 0, time.UTC)},
		{"letsencrypt-fullchain.pem", time.Date(2019, 9, 15, 11, 11, 11, 0, time.UTC)},
	}

	// Set timezone to fixate serialization of datetime
	loc, err := time.LoadLocation("UTC")
	if err != nil {
		t.Fatal(err)
	}
	time.Local = loc

	roots := loadRoots(t)

	for _, tt := range testCases {
		filename := filepath.Join("testdata", tt.filename)
		golden := filepath.Join("testdata", tt.filename+".golden")

		certs, err := load(filename)
		if err != nil {
			t.Fatal(err)
		}
		certs.Verify(true, tt.t, roots)

		// enforce color output
		color.NoColor = false

		got := certs.String()

		if *update {
			os.WriteFile(golden, []byte(got), 0644)
		}

		wantBytes, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		want := string(wantBytes)

		if got != want {
			t.Errorf("%s serialization doesn't match golden file %s:\n%v", filename, golden, diff.LineDiff(want, got))
		}
	}
}

func loadRoots(t *testing.T) *x509.CertPool {
	roots := x509.NewCertPool()

	rootsPEM, err := os.ReadFile("testdata/roots.pem")
	if err != nil {
		t.Fatal(err)
	}

	if !roots.AppendCertsFromPEM(rootsPEM) {
		t.Fatal(err)
	}

	return roots
}
