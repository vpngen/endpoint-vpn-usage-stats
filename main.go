package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
)

func main() {
	wgi := flag.String("wgi", "", "wg interface, ex. wg0, required")
	debug := flag.Bool("debug", false, "debug logging, indented json output")
	flag.Parse()

	var logFlags int
	if *debug {
		logFlags = log.Lshortfile
	}

	logger := log.New(os.Stderr, "", logFlags)

	res := stat{
		Code: 0,
		Data: data{
			Aggregated: aggregated{
				"wireguard":     1,
				"ipcsec":        0,
				"cloak-openvpn": 0,
				"outline-ss":    1,
			},
			Traffic:   make(peer[traffic]),
			LastSeen:  make(peer[lastSeen]),
			Endpoints: make(peer[endpoints]),
		},
	}

	// wireguard
	wgTraffic, err := getWgTransfer(*wgi)
	if err != nil {
		logger.Fatal("wg show transfer:", err)
	}
	mergePeers(res.Data.Traffic, wgTraffic)

	wgLastSeen, err := getWgLatestHandshakes(*wgi)
	if err != nil {
		logger.Fatal("wg show latest-handshakes:", err)
	}
	mergePeers(res.Data.LastSeen, wgLastSeen)

	wgEndpoints, err := getWgEndpoints(*wgi)
	if err != nil {
		logger.Fatal("wg show endpoints:", err)
	}
	mergePeers(res.Data.Endpoints, wgEndpoints)

	//ipsec
	file, err := os.Open("/etc/accel-ppp.chap-secrets." + *wgi)
	if err != nil {
		logger.Fatal("ipsec secrets file:", err)
	}
	username2peer, err := parseIpsecSecrets(file)
	if err != nil {
		logger.Fatal("parse ipsec secrets:", err)
	}
	if err = file.Close(); err != nil {
		logger.Fatal("close ipsec secrets file:", err)
	}

	ipsecTraffic, err := getIpsecTraffic(*wgi, username2peer)
	if err != nil {
		logger.Fatal("ipsec traffic:", err)
	}
	mergePeers(res.Data.Traffic, ipsecTraffic)

	mergePeers(res.Data.LastSeen, parseIpsecLastSeen(username2peer))

	ipsecEndpoints, err := getIpsecEndpoints(*wgi, username2peer)
	if err != nil {
		logger.Fatal("ipsec endpoints:", err)
	}
	mergePeers(res.Data.Endpoints, ipsecEndpoints)

	//cloak-openvpn

	//outline-ss

	encoder := json.NewEncoder(os.Stdout)
	if *debug {
		encoder.SetIndent("", "  ")
	}
	if err = encoder.Encode(res); err != nil {
		logger.Fatal("json encode:", err)
	}
}
