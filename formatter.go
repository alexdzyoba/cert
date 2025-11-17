package main

type Formatter interface {
	Format(report *Report) (string, error)
}
