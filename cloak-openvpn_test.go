package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOpenvpnTraffic(t *testing.T) {
	statusFile, err := os.Open("status.log")
	if err != nil {
		t.Fatal(err)
	}
	peerFile, err := os.Open("openvpn-ccd")
	if err != nil {
		t.Fatal(err)
	}
	status, err := getOpenVPNStatus(statusFile, peerFile)
	if err != nil {
		t.Fatal(err)
	}
	peers := getOpenVPNTraffic(status)

	res, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}

func TestOpenvpnLastSeen(t *testing.T) {
	statusFile, err := os.Open("status.log")
	if err != nil {
		t.Fatal(err)
	}
	peerFile, err := os.Open("openvpn-ccd")
	if err != nil {
		t.Fatal(err)
	}
	status, err := getOpenVPNStatus(statusFile, peerFile)
	if err != nil {
		t.Fatal(err)
	}
	peers := getOpenVPNLastSeen(status)

	res, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}

func TestOpenvpnEndpoints(t *testing.T) {
	statusFile, err := os.Open("status.log")
	if err != nil {
		t.Fatal(err)
	}
	peerFile, err := os.Open("openvpn-ccd")
	if err != nil {
		t.Fatal(err)
	}
	status, err := getOpenVPNStatus(statusFile, peerFile)
	if err != nil {
		t.Fatal(err)
	}
	authDbFile, err := os.Open("userauthdb.log")
	if err != nil {
		t.Fatal(err)
	}
	ep, err := getOpenVPNEndpoints(authDbFile, status)
	if err != nil {
		t.Fatal(err)
	}
	res, err := json.MarshalIndent(ep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}

//func TestParseIpsecTraffic(t *testing.T) {
//	file, err := os.Open("accel-cmd.2.log")
//	if err != nil {
//		t.Fatal(err)
//	}
//	defer file.Close()
//
//	peers, err := parseIpsecTraffic(file, username2peer)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	res, err := json.MarshalIndent(peers, "", "  ")
//	if err != nil {
//		t.Fatal(err)
//	}
//	t.Log(string(res))
//}
