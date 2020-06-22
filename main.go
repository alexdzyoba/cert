package main

import (
	"crypto/tls"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/alexdzyoba/cert/certificate"
	"github.com/alexdzyoba/cert/dump"
	"github.com/alexdzyoba/cert/parser"
)

func main() {
	timeString := flag.String("time", "", "date and time in RFC3339 format")
	noChain := flag.Bool("nochain", false, "disable chain validation")
	flag.Parse()

	var err error

	t := time.Now()
	if *timeString != "" {
		t, err = time.Parse(time.RFC3339, *timeString)
		if err != nil {
			log.Fatal(err)
		}
	}

	resource := flag.Args()[0]

	var entities []*parser.Entity

	_, err = os.Stat(resource)
	if os.IsNotExist(err) {
		entities, err = fromURL(resource)
	} else {
		entities, err = fromFile(resource)
	}
	if err != nil {
		log.Fatal(err)
	}

	if len(entities) > 1 && !*noChain {
		verifyChain(entities, t)
	}

	p := dump.Printer{NoChain: *noChain}
	p.Dump(entities)
}

func fromURL(URL string) ([]*parser.Entity, error) {
	addr, err := addrFromString(URL)
	if err != nil {
		return nil, errors.Wrap(err, "building addr")
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to connect to %v", URL)
	}

	var entities []*parser.Entity
	for _, c := range conn.ConnectionState().PeerCertificates {
		entities = append(entities, &parser.Entity{
			Type: parser.BlockTypeCertificate,
			Val:  certificate.FromX509Cert(c),
		})
	}

	return entities, nil
}

func fromFile(filename string) ([]*parser.Entity, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil && !os.IsNotExist(err) {
		log.Fatal(err)
	}

	return parser.Parse(data)
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

func verifyChain(entities []*parser.Entity, t time.Time) {
	var certs []*certificate.Cert

	for _, e := range entities {
		cert, ok := e.Val.(*certificate.Cert)
		if ok {
			certs = append(certs, cert)
		}
	}

	certificate.VerifyChain(certs, t)
}
