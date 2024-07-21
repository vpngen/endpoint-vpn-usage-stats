package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"testing"
)

//go:embed test_data
var cloakTestDataFS embed.FS

const cloakTestWgi = "wg7"

func TestGetCloakEndpointsMap(t *testing.T) {
	rootFS, err := fs.Sub(cloakTestDataFS, "test_data")
	if err != nil {
		t.Fatal(err)
	}

	epMap, err := getCloakEndpointsMap(&appOptions{
		rootFS: rootFS,
		wgi:    cloakTestWgi,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := json.MarshalIndent(epMap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(res))
}
