package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"testing"
)

//go:embed test_data
var outlineTestDataFS embed.FS

const outlineTestWgi = "wg7"

func TestOutlineTraffic(t *testing.T) {
	rootFS, err := fs.Sub(outlineTestDataFS, "test_data")
	if err != nil {
		t.Fatal(err)
	}

	file, err := rootFS.Open("outputs/outline-metrics.log")
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
	rootFS, err := fs.Sub(outlineTestDataFS, "test_data")
	if err != nil {
		t.Fatal(err)
	}

	file, err := rootFS.Open(fmt.Sprintf("opt/outline-ss-%s/authdb.log", outlineTestWgi))
	if err != nil {
		t.Fatal(err)
	}

	ls, _, ep, err := parseOutlineLastSeenAndEndpoints(file, []string{"127.0.0.1/24"})
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
