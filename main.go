package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	logger *log.Logger
	debug  bool
)

func debugLog(v ...any) {
	if debug {
		logger.Println(v...)
	}
}

func main() {
	wgi := flag.String("wgi", "", "wg interface, e.g. wg0, required")
	flag.BoolVar(&debug, "debug", false, "print errors to stderr, indented json output")
	flag.Parse()

	if *wgi == "" {
		flag.Usage()
		os.Exit(1)
	}

	var logFlags int
	if debug {
		logFlags = log.Lshortfile
	}
	logger = log.New(os.Stderr, "", logFlags)

	res := stat{
		Code: 0,
		Data: data{
			Aggregated: aggregated{
				"wireguard":     1,
				"ipsec":         0,
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
		debugLog("wg show transfer:", err)
	} else {
		mergePeers(res.Data.Traffic, wgTraffic)
	}

	wgLastSeen, err := getWgLatestHandshakes(*wgi)
	if err != nil {
		debugLog("wg show latest-handshakes:", err)
	} else {
		mergePeers(res.Data.LastSeen, wgLastSeen)
	}

	wgEndpoints, err := getWgEndpoints(*wgi)
	if err != nil {
		debugLog("wg show endpoints:", err)
	} else {
		mergePeers(res.Data.Endpoints, wgEndpoints)
	}

	// ipsec
	if err = getIPSec(*wgi, res); err != nil {
		debugLog("ipsec:", err)
	}

	// cloak-openvpn
	if err = getOVC(*wgi, res); err != nil {
		debugLog("cloak-openvpn:", err)
	}

	// outline-ss
	if err = getOutline(*wgi, res); err != nil {
		debugLog("outline-ss:", err)
	}

	// output
	encoder := json.NewEncoder(os.Stdout)
	if debug {
		encoder.SetIndent("", "  ")
	}
	if err = encoder.Encode(res); err != nil {
		logger.Fatal("json encode:", err)
	}
}

func getIPSec(wgi string, res stat) error {
	file, err := os.Open("/etc/accel-ppp.chap-secrets." + wgi)
	if err != nil {
		return fmt.Errorf("ipsec secrets file: %w", err)
	}
	defer file.Close()

	username2peer, err := parseIpsecSecrets(file)
	if err != nil {
		return fmt.Errorf("parse ipsec secrets: %w", err)
	}

	ipsecTraffic, err := getIpsecTraffic(wgi, username2peer)
	if err != nil {
		return fmt.Errorf("ipsec traffic: %w", err)
	}
	mergePeers(res.Data.Traffic, ipsecTraffic)

	mergePeers(res.Data.LastSeen, parseIpsecLastSeen(username2peer))

	ipsecEndpoints, err := getIpsecEndpoints(wgi, username2peer)
	if err != nil {
		return fmt.Errorf("ipsec endpoints: %w", err)
	}
	mergePeers(res.Data.Endpoints, ipsecEndpoints)

	return nil
}

func getOVC(wgi string, res stat) error {
	statusFile, err := os.Open(fmt.Sprintf("/opt/openvpn-%s/status.log", wgi))
	if err != nil {
		return fmt.Errorf("openvpn status file: %w", err)
	}
	defer statusFile.Close()

	peersReader, err := runcmd("grep", "-rH", "^#", fmt.Sprintf("/opt/openvpn-%s/ccd/", wgi))
	if err != nil {
		return fmt.Errorf("openvpn peers file: %w", err)
	}
	status, err := getOpenVPNStatus(statusFile, peersReader)
	if err != nil {
		return fmt.Errorf("parse openvpn status: %w", err)
	}
	mergePeers(res.Data.Traffic, getOpenVPNTraffic(status))

	mergePeers(res.Data.LastSeen, getOpenVPNLastSeen(status))

	authDbFile, err := os.Open(fmt.Sprintf("/opt/cloak-%s/userinfo/userauthdb.log", wgi))
	if err != nil {
		return fmt.Errorf("openvpn authdb file: %w", err)
	}
	defer authDbFile.Close()

	ovpnEndpoints, err := getOpenVPNEndpoints(authDbFile, status)
	if err != nil {
		return fmt.Errorf("openvpn endpoints: %w", err)
	}
	mergePeers(res.Data.Endpoints, ovpnEndpoints)

	return nil
}

func getOutline(wgi string, res stat) error {
	outlineTraffic, err := getOutlineTraffic(wgi)
	if err != nil {
		return fmt.Errorf("traffic: %w", err)
	}
	mergePeers(res.Data.Traffic, outlineTraffic)

	outlineLastSeen, outlineEndpoints, err := getOutlineLastSeenAndEndpoints(wgi)
	if err != nil {
		return fmt.Errorf("last seen and endpoints: %w", err)
	}

	mergePeers(res.Data.LastSeen, outlineLastSeen)
	mergePeers(res.Data.Endpoints, outlineEndpoints)

	return nil
}
