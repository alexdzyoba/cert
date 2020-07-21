package main

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
)

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

func fromReader(r io.Reader) (Certs, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read")
	}

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
