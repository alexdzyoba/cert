package main

import (
	"time"
)

type Config struct {
	Source     string
	Format     string
	Time       time.Time
	Verbosity  OutputLevel
	RootsPath  string
	AppendRoot bool
}
