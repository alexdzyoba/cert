package main

// Formatter converts a verification report to a string representation.
type Formatter interface {
	Format(report Report) (string, error)
}
