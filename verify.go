package main

import (
	"time"
)

type VerifyOptions struct {
	Time      time.Time
	RootsPath string
}

func Verify(bundle *Bundle, opts *VerifyOptions) (*Report, error) {
	return nil, nil
}
