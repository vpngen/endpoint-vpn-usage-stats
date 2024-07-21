package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strconv"
	"time"
)

type appOptions struct {
	rootFS fs.FS
	wgi    string
	stats  *stat
}

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
	wgInterface := flag.String("wgi", "", "wg interface, e.g. wg0, required")
	flag.BoolVar(&debug, "debug", false, "print errors to stderr, indented json output")
	accelCmd := flag.Bool("accel-cmd", false, "accel-cmd data required")

	flag.Parse()

	if *wgInterface == "" {
		flag.Usage()
		os.Exit(1)
	}

	var logFlags int
	if debug {
		logFlags = log.Lshortfile
	}
	logger = log.New(os.Stderr, "", logFlags)

	opts := &appOptions{
		rootFS: os.DirFS("/"),
		wgi:    *wgInterface,
		stats: &stat{
			Code: "0",
			Data: data{
				Aggregated: aggregated{
					protoWireguard:        1,
					protoIPsec:            0,
					protoOpenVPNOverCloak: 0,
					protoOutline:          1,
					protoOutlineOverCloak: 0,
				},
				Traffic:   make(peer[traffic]),
				LastSeen:  make(peer[lastSeen]),
				Endpoints: make(peer[endpoints]),
			},
		},
	}

	// wireguard
	if err := handleWireGuard(opts); err != nil {
		debugLog("wireguard:", err)
	}

	// ipsec
	if *accelCmd {
		if err := handleIPSec(opts); err != nil {
			debugLog("ipsec:", err)
		}
	}

	cloakEndpoints, err := getCloakEndpointsMap(opts)
	if err != nil {
		debugLog("cloak endpoints:", err)
	}

	// cloak-openvpn
	if err = handleOVC(opts, cloakEndpoints); err != nil {
		debugLog("cloak-openvpn:", err)
	}

	// outline-ss
	if err = handleOutline(opts, cloakEndpoints); err != nil {
		debugLog("outline-ss:", err)
	}

	opts.stats.Timestamp = strconv.FormatInt(time.Now().Unix(), 10)

	// output
	encoder := json.NewEncoder(os.Stdout)
	if debug {
		encoder.SetIndent("", "  ")
	}
	if err = encoder.Encode(opts.stats); err != nil {
		logger.Fatal("json encode:", err)
	}
}

func handleWireGuard(o *appOptions) error {
	// wireguard
	wgTraffic, errTraffic := getWgTransfer(o.wgi)
	if errTraffic != nil {
		debugLog("wg show transfer:", errTraffic)
	}

	mergePeers(o.stats.Data.Traffic, wgTraffic)

	wgLastSeen, errLastSeen := getWgLatestHandshakes(o.wgi)
	if errLastSeen != nil {
		debugLog("wg show latest-handshakes:", errLastSeen)
	}

	mergePeers(o.stats.Data.LastSeen, wgLastSeen)

	wgEndpoints, errEndpoints := getWgEndpoints(o.wgi)
	if errEndpoints != nil {
		debugLog("wg show endpoints:", errEndpoints)
	}

	mergePeers(o.stats.Data.Endpoints, wgEndpoints)

	return errors.Join(errTraffic, errLastSeen, errEndpoints)
}

func handleIPSec(o *appOptions) error {
	file, err := o.rootFS.Open("etc/accel-ppp.chap-secrets." + o.wgi)
	if err != nil {
		return fmt.Errorf("ipsec secrets file: %w", err)
	}

	defer file.Close()

	username2peer, err := parseIpsecSecrets(file)
	if err != nil {
		return fmt.Errorf("parse ipsec secrets: %w", err)
	}

	ipsecTraffic, err := getIpsecTraffic(o.wgi, username2peer)
	if err != nil {
		return fmt.Errorf("ipsec traffic: %w", err)
	}

	mergePeers(o.stats.Data.Traffic, ipsecTraffic)
	mergePeers(o.stats.Data.LastSeen, parseIpsecLastSeen(username2peer))

	ipsecEndpoints, err := getIpsecEndpoints(o.wgi, username2peer)
	if err != nil {
		return fmt.Errorf("ipsec endpoints: %w", err)
	}

	mergePeers(o.stats.Data.Endpoints, ipsecEndpoints)

	return nil
}

func handleOVC(o *appOptions, cloakEndpoints map[string]string) error {
	statusFile, err := o.rootFS.Open(fmt.Sprintf("opt/openvpn-%s/status.log", o.wgi))
	if err != nil {
		return fmt.Errorf("openvpn status file: %w", err)
	}

	defer statusFile.Close()

	peersReader, err := fs.ReadDir(o.rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", o.wgi))
	if err != nil {
		return fmt.Errorf("openvpn grep peers: %w", err)
	}

	cnMap, uidMap, err := getOVCPeerMaps(o.rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", o.wgi), peersReader)
	if err != nil {
		return fmt.Errorf("openvpn peer maps: %w", err)
	}

	status, err := getOpenVPNStatus(statusFile, cnMap)
	if err != nil {
		return fmt.Errorf("parse openvpn status: %w", err)
	}

	mergePeers(o.stats.Data.Traffic, assembleOpenVPNTraffic(status))
	mergePeers(o.stats.Data.LastSeen, assembleOpenVPNLastSeen(status))

	ovpnEndpoints, err := assembleOVCEndpoints(cloakEndpoints, uidMap, status)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openvpn endpoints: %s\n", err)

		// return fmt.Errorf("openvpn endpoints: %w", err)
	}

	mergePeers(o.stats.Data.Endpoints, ovpnEndpoints)

	return nil
}

func handleOutline(o *appOptions, cloakEndpoints map[string]string) error {
	port, addr, err := getOutlinePortFromWgQuick(o.rootFS, o.wgi)
	if err != nil {
		return fmt.Errorf("get outline port: %w", err)
	}

	outlineTraffic, err := getOutlineTraffic(o.wgi, port)
	if err != nil {
		return fmt.Errorf("traffic: %w", err)
	}
	mergePeers(o.stats.Data.Traffic, outlineTraffic)

	outlineLastSeen, outlineCloakLastSeen, outlineEndpoints, err := getOutlineLastSeenAndEndpoints(o.rootFS, o.wgi, addr)
	if err != nil {
		return fmt.Errorf("last seen and endpoints: %w", err)
	}

	mergePeers(o.stats.Data.LastSeen, outlineLastSeen)
	mergePeers(o.stats.Data.Endpoints, outlineEndpoints)

	// over cloak.

	peersReader, err := fs.ReadDir(o.rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", o.wgi))
	if err != nil {
		return fmt.Errorf("openvpn grep peers: %w", err)
	}

	_, uidMap, err := getOVCPeerMaps(o.rootFS, fmt.Sprintf("opt/openvpn-%s/ccd", o.wgi), peersReader)
	if err != nil {
		return fmt.Errorf("openvpn peer maps: %w", err)
	}

	olcEndpoints, err := assembleOLCEndpoints(cloakEndpoints, uidMap, outlineCloakLastSeen)
	if err != nil {
		return fmt.Errorf("outline endpoints: %w", err)
	}

	mergePeers(o.stats.Data.Endpoints, olcEndpoints)

	return nil
}
