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

const (
	timeout = 5 * time.Second
)

// Load gets the bundle from source
func Load(source string) (*Bundle, error) {
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
	} else {
		defer f.Close()
		return fromReader(f)
	}
}

func fromReader(r io.Reader) (*Bundle, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	var bundle Bundle
	for block := range NewPEMParser(data).Blocks() {
		cert, err := NewCertificate(block)
		if err != nil {
			return nil, err
		}
		bundle = append(bundle, cert)
	}
	return &bundle, nil
}

func fromURL(source string) (*Bundle, error) {
	addr, err := buildTLSAddr(source)
	if err != nil {
		return nil, fmt.Errorf("build TLS address: %w", err)
	}

	dialer := &net.Dialer{Timeout: timeout}
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

	return &bundle, nil
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
