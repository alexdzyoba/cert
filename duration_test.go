package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDurationString(t *testing.T) {
	tests := []struct {
		d Duration
		s string
	}{
		{Duration(24 * time.Hour), "1.0 days"},
		{Duration(9 * 24 * time.Hour), "1.3 weeks"},
		{Duration(65 * 24 * time.Hour), "2.2 months"},
		{Duration(800 * 24 * time.Hour), "2.2 years"},
		{Duration(37000 * 24 * time.Hour), "101.4 years"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.s, tt.d.String())
	}
}
