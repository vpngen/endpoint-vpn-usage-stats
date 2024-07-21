package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"testing"
)

//go:embed test_data
var ovcTestDataFS embed.FS

const ovcTestWgi = "wg7"

func TestOpenvpnTraffic(t *testing.T) {
	rootFS, err := fs.Sub(ovcTestDataFS, "test_data")
	if err != nil {
		t.Fatal(err)
	}

	peersReader, err := fs.ReadDir(rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", ovcTestWgi))
	if err != nil {
		t.Fatal(err)
	}

	cnMap, _, err := getOVCPeerMaps(rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", ovcTestWgi), peersReader)
	if err != nil {
		t.Fatal(err)
	}

	statusFile, err := rootFS.Open(fmt.Sprintf("opt/openvpn-%s/status.log", ovcTestWgi))
	if err != nil {
		t.Fatal(err)
	}

	defer statusFile.Close()

	status, err := getOpenVPNStatus(statusFile, cnMap)
	if err != nil {
		t.Fatal(err)
	}
	peers := assembleOpenVPNTraffic(status)

	res, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(res))
}

func TestOpenvpnLastSeen(t *testing.T) {
	rootFS, err := fs.Sub(ovcTestDataFS, "test_data")
	if err != nil {
		t.Fatal(err)
	}

	peersReader, err := fs.ReadDir(rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", ovcTestWgi))
	if err != nil {
		t.Fatal(err)
	}

	cnMap, _, err := getOVCPeerMaps(rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", ovcTestWgi), peersReader)
	if err != nil {
		t.Fatal(err)
	}

	statusFile, err := rootFS.Open(fmt.Sprintf("opt/openvpn-%s/status.log", ovcTestWgi))
	if err != nil {
		t.Fatal(err)
	}

	defer statusFile.Close()

	status, err := getOpenVPNStatus(statusFile, cnMap)
	if err != nil {
		t.Fatal(err)
	}

	peers := assembleOpenVPNLastSeen(status)

	res, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(res))
}

func TestOpenvpnEndpoints(t *testing.T) {
	rootFS, err := fs.Sub(ovcTestDataFS, "test_data")
	if err != nil {
		t.Fatal(err)
	}

	peersReader, err := fs.ReadDir(rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", ovcTestWgi))
	if err != nil {
		t.Fatal(err)
	}

	cnMap, uidMap, err := getOVCPeerMaps(rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", ovcTestWgi), peersReader)
	if err != nil {
		t.Fatal(err)
	}

	statusFile, err := rootFS.Open(fmt.Sprintf("opt/openvpn-%s/status.log", ovcTestWgi))
	if err != nil {
		t.Fatal(err)
	}

	defer statusFile.Close()

	status, err := getOpenVPNStatus(statusFile, cnMap)
	if err != nil {
		t.Fatal(err)
	}

	cloakEndpoints, err := getCloakEndpointsMap(&appOptions{
		rootFS: rootFS,
		wgi:    ovcTestWgi,
	})
	if err != nil {
		debugLog("cloak endpoints:", err)
	}

	ep, err := assembleOVCEndpoints(cloakEndpoints, uidMap, status)
	if err != nil {
		t.Fatal(err)
	}

	res, err := json.MarshalIndent(ep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(res))
}
