package main

import "testing"

func TestBuildTLSAddr(t *testing.T) {
	testCases := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"example.com", "example.com:443", false},
		{"https://www.example.com", "www.example.com:443", false},
		{"https://example.com/some/?q=1#id", "example.com:443", false},
		{"//example.com/", "example.com:443", false},
		{"examplecom\\", "", true},
		{"tcp+tls://backend:8000/", "backend:8000", false},
	}

	for _, c := range testCases {
		got, err := buildTLSAddr(c.input)
		if got != c.want {
			t.Errorf("addrFromString(%v) == %v, want %v", c.input, got, c.want)
		}

		if (err != nil) != c.wantErr {
			t.Errorf("addrFromString(%v) expected error", c.input)
		}
	}
}
