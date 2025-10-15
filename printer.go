package main

type BundlePrinter interface {
	Print(Bundle, *Roots) (string, error)
}
