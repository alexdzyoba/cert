package main

import (
	"time"

	"github.com/alexdzyoba/cert/format"
)

type Config struct {
	Source     string
	Format     string
	Time       time.Time
	Verbosity  format.OutputLevel
	RootsPath  string
	AppendRoot bool
}
