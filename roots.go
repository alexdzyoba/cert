package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

/*
 * Discover root certificates. This mostly copies go's crypto/x509 package
 * logic. In comparison to x509.CertPool this provide API to get certificate
 * from the roots pool and compare using fingerprint, not subject name
 */

const (
	// certFileEnv is the environment variable which identifies where to locate
	// the SSL certificate file. If set this overrides the system default.
	certFileEnv = "SSL_CERT_FILE"

	// certDirEnv is the environment variable which identifies which directory
	// to check for SSL certificate files. If set this overrides the system default.
	// It is a colon separated list of directories.
	// See https://www.openssl.org/docs/man1.0.2/man1/c_rehash.html.
	certDirEnv = "SSL_CERT_DIR"
)

// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
}

// Possible directories with certificate files; all will be read.
var certDirectories = []string{
	"/etc/ssl/certs",     // SLES10/SLES11, https://golang.org/issue/12139
	"/etc/pki/tls/certs", // Fedora/RHEL
}

type Roots struct {
	*x509.CertPool
	certs map[[32]byte]*Cert // fingerprint(sha256) => certificate
}

func NewRoots() *Roots {
	return &Roots{
		CertPool: x509.NewCertPool(),
		certs:    make(map[[32]byte]*Cert),
	}
}

func SystemRoots() (*Roots, error) {
	roots := NewRoots()

	files := certFiles
	if f := os.Getenv(certFileEnv); f != "" {
		files = []string{f}
	}

	var firstErr error
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err == nil {
			roots.AppendCertsFromPEM(data)
			roots.CertPool.AppendCertsFromPEM(data)
			break
		}
		if firstErr == nil && !os.IsNotExist(err) {
			firstErr = err
		}
	}

	dirs := certDirectories
	if d := os.Getenv(certDirEnv); d != "" {
		// OpenSSL and BoringSSL both use ":" as the SSL_CERT_DIR separator.
		// See:
		//  * https://golang.org/issue/35325
		//  * https://www.openssl.org/docs/man1.0.2/man1/c_rehash.html
		dirs = strings.Split(d, ":")
	}

	for _, directory := range dirs {
		fis, err := readUniqueDirectoryEntries(directory)
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		for _, fi := range fis {
			data, err := os.ReadFile(directory + "/" + fi.Name())
			if err == nil {
				roots.AppendCertsFromPEM(data)
				roots.CertPool.AppendCertsFromPEM(data)
			}
		}
	}

	if roots.len() > 0 || firstErr == nil {
		return roots, nil
	}

	return nil, firstErr
}

func (r *Roots) AppendCertsFromPEM(data []byte) bool {
	ok := false
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		if block.Type == PEMCertType {
			cert, err := FromBytes(block.Bytes)
			if err != nil {
				continue
			}
			r.certs[cert.fingerprint] = cert
			ok = true
		}
	}
	return ok
}

func (r *Roots) len() int {
	return len(r.certs)
}

func (r *Roots) Match(fingerprint [32]byte) bool {
	_, ok := r.certs[fingerprint]
	return ok
}

func (r *Roots) FindFrom(cert *Cert) {
	fmt.Printf("%#v\n", cert.RawIssuer)

	issuer, err := x509.ParseCertificate(cert.RawIssuer)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", issuer)
}

// readUniqueDirectoryEntries is like os.ReadDir but omits
// symlinks that point within the directory.
func readUniqueDirectoryEntries(dir string) ([]fs.DirEntry, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	uniq := files[:0]
	for _, f := range files {
		if !isSameDirSymlink(f, dir) {
			uniq = append(uniq, f)
		}
	}
	return uniq, nil
}

// isSameDirSymlink reports whether fi in dir is a symlink with a
// target not containing a slash.
func isSameDirSymlink(f fs.DirEntry, dir string) bool {
	if f.Type()&fs.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(filepath.Join(dir, f.Name()))
	return err == nil && !strings.Contains(target, "/")
}
