package main

type Record struct {
	Cert   *Certificate
	Error  error
	IsRoot bool
	IsCA   bool
}

type Report []*Record
