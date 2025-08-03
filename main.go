package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"
)

func main() {
	var (
		timeString string
		noChain    bool
		verbose    bool
		pemOutput  bool
		rootsPath  string
	)

	pflag.Usage = func() {
		fmt.Fprintf(pflag.CommandLine.Output(), "Usage: %s [options] <file or URL>\n", os.Args[0])
		fmt.Fprintf(pflag.CommandLine.Output(), "\nOptions:\n")
		pflag.PrintDefaults()
	}

	pflag.StringVarP(&timeString, "time", "t", "", "Override date and time for validation (RFC3339 format)")
	pflag.BoolVarP(&noChain, "nochain", "n", false, "disable chain validation")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	pflag.StringVarP(&rootsPath, "roots", "r", "", "path to root certificates bundle in PEM format")
	pflag.BoolVarP(&pemOutput, "pem", "p", false, "output in PEM format instead of text")
	pflag.Parse()

	if len(pflag.Args()) != 1 {
		pflag.Usage()
		os.Exit(1)
	}

	var err error

	// Override time from flag
	t := time.Now()
	if timeString != "" {
		t, err = time.Parse(time.RFC3339, timeString)
		if err != nil {
			log.Fatal(err)
		}
	}

	resource := pflag.Args()[0]

	bundle, err := load(resource)
	if err != nil {
		log.Fatal(err)
	}

	var roots *x509.CertPool
	if rootsPath != "" {
		data, err := os.ReadFile(rootsPath)
		if err != nil {
			log.Fatalf("cannot read roots bundle file %q: %v", rootsPath, err)
		}

		roots = x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(data)
		if !ok {
			log.Fatalf("no root certificate was parsed from %q", rootsPath)
		}
	}

	asChain := len(bundle) > 1 && !noChain
	err = bundle.Verify(asChain, t, roots)
	if err != nil {
		log.Fatalf("failed to verify: %v", err)
	}

	if pemOutput {
		pem, err := bundle.AsPEM()
		if err != nil {
			log.Fatalf("cannot serialize to PEM: %v", err)
		}
		fmt.Print(pem)
	} else {
		fmt.Print(bundle)
	}
}

// load determines the type of resource and loads certificates bundle from it
func load(resource string) (Bundle, error) {
	var (
		bundle Bundle
		f      *os.File
		err    error
	)

	if resource == "-" {
		f = os.Stdin
		err = nil
	} else {
		f, err = os.Open(resource)
	}

	if errors.Is(err, os.ErrNotExist) {
		bundle, err = fromURL(resource)
	} else {
		bundle, err = fromReader(f)
	}
	if err != nil {
		return nil, errors.Wrap(err, "loading bundle")
	}

	return bundle, nil
}

// fromURL attempts to parse certificates bundle from the given URL
func fromURL(URL string) (Bundle, error) {
	addr, err := buildTLSAddr(URL)
	if err != nil {
		return nil, errors.Wrap(err, "building addr")
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %v", URL)
	}

	var bundle Bundle
	for _, c := range conn.ConnectionState().PeerCertificates {
		cert, err := FromX509(c)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse cert")
		}
		bundle = append(bundle, cert)
	}

	return bundle, nil
}

// fromReader parses PEM-encoded certificates bundle from io.Reader r
func fromReader(r io.Reader) (Bundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read")
	}

	var bundle Bundle
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == PEMCertType {
			cert, err := FromBytes(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "parsing certificate")
			}

			bundle = append(bundle, cert)
		}
	}

	return bundle, nil
}

// buildTLSAddr creates address suitable for tls.DialWithDialer from s
func buildTLSAddr(s string) (string, error) {
	// Ensure "//" for url.Parse
	match, err := regexp.MatchString(`(https?:)?//`, s)
	if err != nil {
		return "", errors.Wrap(err, "matching URL")
	}

	if !match {
		s = "//" + s
	}

	// Parse as URL and leave only host with port 443
	u, err := url.Parse(s)
	if err != nil {
		return "", errors.Wrap(err, "parsing URL")
	}

	parts := strings.Split(u.Host, ":")
	return net.JoinHostPort(parts[0], "443"), nil
}
