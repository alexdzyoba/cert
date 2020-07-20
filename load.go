package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
)

func fromURL(URL string) (Certs, error) {
	addr, err := addrFromString(URL)
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
		certs = append(certs, FromX509Cert(c))
	}

	return certs, nil
}

func fromFile(filename string) (Certs, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	return Parse(data)
}

func addrFromString(s string) (string, error) {
	match, err := regexp.MatchString(`(https?:)?//`, s)
	if err != nil {
		return "", errors.Wrap(err, "matching URL")
	}

	if !match {
		s = "//" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return "", errors.Wrap(err, "parsing URL")
	}

	parts := strings.Split(u.Host, ":")
	return net.JoinHostPort(parts[0], "443"), nil
}
