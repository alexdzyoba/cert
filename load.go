package main

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// load decide where to load certs from
func load(resource string) (Certs, error) {
	var certs Certs
	f, err := os.Open(resource)
	if errors.Is(err, os.ErrNotExist) {
		certs, err = fromURL(resource)
	} else {
		certs, err = fromReader(f)
	}
	if err != nil {
		return nil, errors.Wrap(err, "loading certs")
	}

	return certs, nil
}

func fromURL(URL string) (Certs, error) {
	addr, err := buildTLSAddr(URL)
	if err != nil {
		return nil, errors.Wrap(err, "building addr")
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %v", URL)
	}

	var certs Certs
	for _, c := range conn.ConnectionState().PeerCertificates {
		cert, err := FromX509Cert(c)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse cert")
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

// fromReader parses PEM-encoded certificates from io.Reader r
func fromReader(r io.Reader) (Certs, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read")
	}

	const PEMCertType = "CERTIFICATE"

	certs := make([]*Cert, 0)
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == PEMCertType {
			cert, err := FromBytes(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "parsing certificate")
			}

			certs = append(certs, cert)
		}
	}

	return certs, nil
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
