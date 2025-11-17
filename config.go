package main

import (
	"time"
)

type Config struct {
	Source     string
	Format     Format
	Time       time.Time
	Verbosity  OutputLevel
	RootsPath  string
	AppendRoot bool
}
