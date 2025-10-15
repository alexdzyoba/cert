package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"time"
)

// Timeout is the default timeout for TLS connections when loading certificates from URLs.
var Timeout = 5 * time.Second

// Load loads certificates from a file path, stdin ("-"), or URL.
// If the source is not a valid file, it attempts to connect via TLS.
func Load(source string) (Bundle, error) {
	var (
		f   *os.File
		err error
	)

	if source == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(source)
	}

	if errors.Is(err, os.ErrNotExist) {
		return fromURL(source)
	} else if err == nil {
		defer f.Close()
		return fromReader(f)
	} else {
		return nil, fmt.Errorf("open %q: %w", source, err)
	}
}

// LoadMulti loads and combines certificates from multiple sources.
func LoadMulti(sources []string) (Bundle, error) {
	var combined Bundle
	for _, source := range sources {
		bundle, err := Load(source)
		if err != nil {
			return nil, fmt.Errorf("load from %q: %w", source, err)
		}

		combined = append(combined, bundle...)
	}
	return combined, nil
}

func fromReader(r io.Reader) (Bundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	var bundle Bundle
	i := 0
	for block := range PEMBlocks(data) {
		cert, err := NewCertificate(block)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		bundle = append(bundle, cert)
		i++
	}
	return bundle, nil
}

func fromURL(source string) (Bundle, error) {
	addr, err := buildTLSAddr(source)
	if err != nil {
		return nil, fmt.Errorf("build TLS address: %w", err)
	}

	dialer := &net.Dialer{Timeout: Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to %q: %w", source, err)
	}

	var bundle Bundle
	for _, c := range conn.ConnectionState().PeerCertificates {
		cert, err := NewCertificateFromX509(c)
		if err != nil {
			return nil, err
		}
		bundle = append(bundle, cert)
	}

	return bundle, nil
}

// buildTLSAddr creates address from source suitable for tls.DialWithDialer
func buildTLSAddr(source string) (string, error) {
	// Ensure "//" for url.Parse
	match, err := regexp.MatchString(`(https?:)?//`, source)
	if err != nil {
		return "", fmt.Errorf("matching URL: %w", err)
	}

	if !match {
		source = "//" + source
	}

	// Parse as URL and leave only host with port 443
	u, err := url.Parse(source)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}

	port := u.Port()
	if port == "" {
		port = "443"
	}

	return net.JoinHostPort(u.Hostname(), port), nil
}
