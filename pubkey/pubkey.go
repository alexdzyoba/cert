package pubkey

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"

	"github.com/pkg/errors"
)

type Type int

const (
	Unknown Type = iota
	RSA
	DSA
	ECDSA
	ED25519
)

func (t Type) String() string {
	switch t {
	case RSA:
		return "RSA"
	case DSA:
		return "DSA"
	case ECDSA:
		return "ECDSA"
	case ED25519:
		return "ED25519"
	default:
		return "Unknown"
	}
}

// PublicKey wraps various public keys from crypto package
type PublicKey struct {
	Type Type
	val  interface{}
}

func New(pemData []byte) (*PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(pemData)
	if err != nil {
		return nil, errors.Wrap(err, "parse public key")
	}

	var typ Type
	switch pub.(type) {
	case *rsa.PublicKey:
		typ = RSA
	case *dsa.PublicKey:
		typ = DSA
	case *ecdsa.PublicKey:
		typ = ECDSA
	case ed25519.PublicKey:
		typ = ED25519
	default:
		typ = Unknown
	}

	return &PublicKey{
		Type: typ,
		val:  pub,
	}, nil
}

func (pk *PublicKey) Name() string {
	return "Public Key"
}

func (pk *PublicKey) Indent(indent string) string {
	// TODO: Show additional info like key length where possible
	return indent + "Type " + pk.Type.String()
}
