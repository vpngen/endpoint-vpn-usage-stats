package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOutlineTraffic(t *testing.T) {
	file, err := os.Open("outline-metrics.log")
	if err != nil {
		t.Fatal(err)
	}
	peers, err := parseOutlineTraffic(file)
	if err != nil {
		t.Fatal(err)
	}
	res, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}

func TestOutlineLastSeenAndEndpoints(t *testing.T) {
	file, err := os.Open("authdb.log")
	if err != nil {
		t.Fatal(err)
	}
	ls, ep, err := parseOutlineLastSeenAndEndpoints(file)
	if err != nil {
		t.Fatal(err)
	}
	res, err := json.MarshalIndent(ls, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))

	res, err = json.MarshalIndent(ep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}
