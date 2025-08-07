package main

type BundlePrinter interface {
	Print(Bundle) (string, error)
}
