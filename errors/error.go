package errors

import "errors"

var (
	ParseFailure = errors.New("failed to parse input data")
)
