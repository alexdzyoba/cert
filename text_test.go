package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "update golden files")

func TestTextFormat(t *testing.T) {
	tests := []struct {
		file      string
		time      time.Time
		verbosity OutputLevel
		golden    string
	}{
		{
			file:      "example.com.crt",
			time:      time.Date(2026, 2, 16, 12, 0, 0, 0, time.UTC),
			verbosity: CompactOutput,
			golden:    "example.com.crt.golden",
		},
		{
			file:      "example.com.crt",
			time:      time.Date(2026, 2, 16, 12, 0, 0, 0, time.UTC),
			verbosity: VerboseOutput,
			golden:    "example.com.crt.verbose.golden",
		},
		{
			file:      "example.com.crt",
			time:      time.Date(2026, 2, 16, 12, 0, 0, 0, time.UTC),
			verbosity: FullOutput,
			golden:    "example.com.crt.full.golden",
		},
	}

	// Fix timezone for deterministic output
	time.Local = time.UTC

	for _, tt := range tests {
		bundle, err := Load(filepath.Join("testdata", tt.file))
		if err != nil {
			t.Fatalf("load %s: %v", tt.file, err)
		}

		report, err := Verify(bundle, &VerifyOptions{
			Time: tt.time,
		})
		if err != nil {
			t.Fatalf("verify: %v", err)
		}

		f := &TextFormatter{Verbosity: tt.verbosity}
		got, err := f.Format(report)
		if err != nil {
			t.Fatalf("format: %v", err)
		}

		goldenPath := filepath.Join("testdata", tt.golden)

		if *update {
			if err := os.WriteFile(goldenPath, []byte(got), 0644); err != nil {
				t.Fatalf("write golden: %v", err)
			}
			return
		}

		wantBytes, err := os.ReadFile(goldenPath)
		if err != nil {
			t.Fatalf("read golden (run with -update to create): %v", err)
		}
		want := string(wantBytes)

		if got != want {
			t.Errorf("output doesn't match golden file %s\n--- want ---\n%s\n--- got ---\n%s", tt.golden, want, got)
		}
	}
}
