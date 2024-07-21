package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"strconv"
	"testing"
	"time"
)

//go:embed test_data
var ipsecTestDataFS embed.FS

const ipsecTestWgi = "wg7"

func TestIpsecTraffic(t *testing.T) {
	rootFS, err := fs.Sub(ipsecTestDataFS, "test_data")
	if err != nil {
		t.Fatal(err)
	}

	username2peer := testGetIpsecSecret(t)

	file, err := rootFS.Open("outputs/ipsec-traffic.log")
	if err != nil {
		t.Fatal(err)
	}

	defer file.Close()

	peers, err := parseIpsecTraffic(file, username2peer)
	if err != nil {
		t.Fatal(err)
	}

	res, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}

func TestIpsecLastSeen(t *testing.T) {
	username2peer := testGetIpsecSecret(t)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	peers := make(peer[lastSeen])
	for _, p := range username2peer {
		peers[p] = map[string]lastSeen{protoIPsec: {Timestamp: ts}}
	}
	res, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}

/*
func TestIpsecEndpoints(t *testing.T) {
	username2peer := testGetIpsecSecret(t)
	file, err := os.Open("accel-cmd.1.log")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	peers, err := parseIpsecEndpoints(file, username2peer)
	if err != nil {
		t.Fatal(err)
	}
	res, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}
*/

func testGetIpsecSecret(t *testing.T) map[string]string {
	rootFS, err := fs.Sub(ipsecTestDataFS, "test_data")
	if err != nil {
		t.Fatal(err)
	}

	file, err := rootFS.Open("etc/accel-ppp.chap-secrets." + ipsecTestWgi)
	if err != nil {
		t.Fatal(err)
	}

	defer file.Close()

	username2peer, err := parseIpsecSecrets(file)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(username2peer)
	if err = file.Close(); err != nil {
		t.Fatal("close ipsec secrets file:", err)
	}

	return username2peer
}
