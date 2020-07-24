package main

import (
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/andreyvit/diff"
	"github.com/fatih/color"
)

func TestChainString(t *testing.T) {
	testCases := []struct {
		filename string
		t        time.Time
	}{
		{
			"google.crt", time.Date(2014, 03, 15, 15, 10, 0, 0, time.UTC),
		},
	}

	for _, c := range testCases {
		filename := filepath.Join("testdata", c.filename)
		golden := filepath.Join("testdata", c.filename+".golden")

		certs, err := load(filename)
		if err != nil {
			t.Fatal(err)
		}

		// enforce color output
		color.NoColor = false

		got := NewChain(certs, c.t, false).String()

		if *update {
			ioutil.WriteFile(golden, []byte(got), 0644)
		}

		wantBytes, err := ioutil.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		want := string(wantBytes)

		if got != want {
			t.Errorf("%s serialization doesn't match golden file %s:\n%v", filename, golden, diff.LineDiff(want, got))
		}
	}
}
