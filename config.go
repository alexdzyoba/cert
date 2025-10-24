package main

import (
	"time"

	"github.com/alexdzyoba/cert/report"
)

type Config struct {
	Source     string
	Format     string
	Time       time.Time
	Verbosity  report.OutputLevel
	RootsPath  string
	AppendRoot bool
}
