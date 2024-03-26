package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestOpenvpnTraffic(t *testing.T) {
	statusFile, err := os.Open("status.log")
	if err != nil {
		t.Fatal(err)
	}
	defer statusFile.Close()

	peerFile, err := os.Open("openvpn-ccd")
	if err != nil {
		t.Fatal(err)
	}
	defer peerFile.Close()

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
	defer statusFile.Close()

	peerFile, err := os.Open("openvpn-ccd")
	if err != nil {
		t.Fatal(err)
	}
	defer peerFile.Close()

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

func TestScanFile(t *testing.T) {
	type testCase struct {
		input string
		name  string
	}
	testCases := []testCase{
		{
			`OpenVPN CLIENT LIST
Updated,2024-03-12 20:05:20
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
pHkXIuK/P+jsVMVXOWrxmKVyBwu/Q/Uup+9HB33+H2w=,1.1.1.1,12345,54321,2024-03-12 20:05:20
BRVNwWdB4JDrZKI0/mf3e/XXfzq/6mR6bHIBN5WsRjQ=,2.2.2.2,12346,54322,2024-03-12 20:05:21
qvZ/LwkLJGOKA717Lz2N7X6MDxp6rMXR3/3CcJQaZEY=,3.3.3.3,12347,54323,2024-03-12 20:05:22
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
GLOBAL STATS
Max bcast/mcast queue length,0
END
`, "valid",
		},
		{
			`OpenVPN CLIENT LIST
Updated,2024-03-12 20:05:20
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
GLOBAL STATS
Max bcast/mcast queue length,0
END
`, "empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := extractOpenVPNStatus(strings.NewReader(tc.input))
			if err != nil {
				t.Error(err)
			}
			t.Log(string(b))
		})
	}
}
