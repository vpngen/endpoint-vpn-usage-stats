package main

import (
	"testing"
)

func TestIP2Subnet(t *testing.T) {
	testCases := []struct {
		in, out string
	}{
		{"91.109.129.83", "91.109.129.0/24"},
		{"217.66.159.255", "217.66.159.0/24"},
		{"217.66.154.35", "217.66.154.0/24"},
	}

	for _, tc := range testCases {
		out, err := get24SubnetFromIP(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		if out != tc.out {
			t.Errorf("expected %q, got %q", tc.out, out)
		}
	}
}
