package main

import (
	"fmt"
	"time"
)

// Duration provides custom time.Duration string serialization
type Duration time.Duration

func (d Duration) String() string {
	const (
		day   = 24
		week  = 7 * day
		month = 30 * day
		year  = 365 * day
	)

	h := time.Duration(d).Hours()
	switch {
	case h >= year:
		return fmt.Sprintf("%.1f years", h/year)
	case h >= month:
		return fmt.Sprintf("%.1f months", h/month)
	case h >= week:
		return fmt.Sprintf("%.1f weeks", h/week)
	case h >= day:
		return fmt.Sprintf("%.1f days", h/day)
	default:
		return fmt.Sprintf("%s", time.Duration(d))
	}
}
