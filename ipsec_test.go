package main

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestIpsecTraffic(t *testing.T) {
	username2peer := testGetIpsecSecret(t)
	file, err := os.Open("accel-cmd.2.log")
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
		peers[p] = map[string]lastSeen{"ipsec": {Timestamp: ts}}
	}
	res, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(res))
}

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

func testGetIpsecSecret(t *testing.T) map[string]string {
	file, err := os.Open("accel-ppp.chap-secrets.wg0")
	if err != nil {
		t.Fatal(err)
	}
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
