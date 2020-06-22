package parser

import (
	"encoding/pem"

	"github.com/pkg/errors"

	"github.com/alexdzyoba/cert/certificate"
	"github.com/alexdzyoba/cert/pubkey"
)

type BlockType int

const (
	BlockTypeUnknown BlockType = iota
	BlockTypeCertificate
	BlockTypePublicKey
)

type Entity struct {
	Type BlockType
	Val  interface{}
}

func Parse(data []byte) ([]*Entity, error) {
	entities := make([]*Entity, 0)
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "PUBLIC KEY":
			pub, err := pubkey.New(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "parsing public key")
			}

			entities = append(entities, &Entity{BlockTypePublicKey, pub})

		case "CERTIFICATE":
			crt, err := certificate.FromBytes(block.Bytes)
			if err != nil {
				return nil, errors.Wrap(err, "parsing certificate")
			}

			entities = append(entities, &Entity{BlockTypeCertificate, crt})

			// default:
			// 	log.Printf("skipping unknown type %s\n", block.Type)
		}
	}

	return entities, nil
}
