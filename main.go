package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"strconv"
	"time"
)

const runCmd = "run"

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
	var logFlags int
	if debug {
		logFlags = log.Lshortfile
	}

	logger = log.New(os.Stderr, "", logFlags)

	// Retrieve the command-line arguments excluding the program name
	args := os.Args[1:]

	if len(args) < 2 {
		flag.Usage()

		os.Exit(1)
	}

	fl := flag.NewFlagSet(runCmd, flag.ExitOnError)

	wgInterface := fl.String("wgi", "", "wg interface, e.g. wg0, required")
	fl.BoolVar(&debug, "debug", false, "print errors to stderr, indented json output")
	accelCmd := fl.Bool("accel-cmd", false, "accel-cmd data required")

	if args[0] != runCmd {
		fl.Parse(args)

		path, err := os.Executable()
		if err != nil {
			logger.Fatal("executable path:", err)
		}

		newargs := []string{"netns", "exec", "ns" + *wgInterface, path, runCmd}
		newargs = append(newargs, args...)

		debugLog("run:", path, newargs)

		cmd := exec.Command("ip", newargs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			logger.Fatal("run ip netns exec:", err)
		}

		os.Exit(0)
	}

	fl.Parse(args[1:])
	if *wgInterface == "" {
		flag.Usage()
		os.Exit(1)
	}

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
					protoProto0:           1,
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

	// proto0
	if err = handleProto0(opts); err != nil {
		debugLog("proto0:", err)
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
	peers, err := getWgPeers(o.wgi)
	if err != nil {
		return fmt.Errorf("wg show peers: %w", err)
	}

	// wireguard
	wgTraffic := getWgTransfer(peers)
	wgLastSeen := getWgLatestHandshakes(peers)
	wgEndpoints := getWgEndpoints(peers)

	mergePeers(o.stats.Data.Traffic, wgTraffic)
	mergePeers(o.stats.Data.LastSeen, wgLastSeen)
	mergePeers(o.stats.Data.Endpoints, wgEndpoints)

	return nil
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

	ipsecTraffic, err := getIpsecTraffic(username2peer)
	if err != nil {
		return fmt.Errorf("ipsec traffic: %w", err)
	}

	mergePeers(o.stats.Data.Traffic, ipsecTraffic)
	mergePeers(o.stats.Data.LastSeen, parseIpsecLastSeen(username2peer))

	ipsecEndpoints, err := getIpsecEndpoints(username2peer)
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

	ovpnEndpoints := assembleOVCEndpoints(cloakEndpoints, uidMap, status)

	mergePeers(o.stats.Data.Endpoints, ovpnEndpoints)

	return nil
}

func handleOutline(o *appOptions, cloakEndpoints map[string]string) error {
	port, addr, err := getOutlinePortFromWgQuick(o.rootFS, o.wgi)
	if err != nil {
		return fmt.Errorf("get outline port: %w", err)
	}

	outlineTraffic, err := getOutlineTraffic(port)
	if err != nil {
		return fmt.Errorf("traffic: %w", err)
	}

	mergePeers(o.stats.Data.Traffic, outlineTraffic)

	outlineLastSeen, outlineCloakLastSeen, outlineEndpoints, err := getOutlineLastSeenAndEndpoints(o.rootFS, o.wgi, addr)
	if err != nil {
		return fmt.Errorf("last seen and endpoints: %w", err)
	}

	mergePeers(o.stats.Data.LastSeen, outlineLastSeen)
	mergePeers(o.stats.Data.LastSeen, outlineCloakLastSeen)
	mergePeers(o.stats.Data.Endpoints, outlineEndpoints)

	// over cloak.

	uidMap, err := getCloakPeerMaps(o.rootFS, fmt.Sprintf("opt/cloak-%s/userinfo/userlist", o.wgi))
	if err != nil {
		return fmt.Errorf("cloak peer maps: %w", err)
	}

	olcEndpoints, err := assembleOLCEndpoints(cloakEndpoints, uidMap)
	if err != nil {
		return fmt.Errorf("outline endpoints: %w", err)
	}

	mergePeers(o.stats.Data.Endpoints, olcEndpoints)

	return nil
}

func handleProto0(o *appOptions) error {
	proto0Traffic, err := getProto0Traffic()
	if err != nil {
		return fmt.Errorf("traffic: %w", err)
	}

	mergePeers(o.stats.Data.Traffic, proto0Traffic)

	proto0LastSeen, proto0Endpoints, err := getProto0LastSeenAndEndpoints(o.rootFS, o.wgi)
	if err != nil {
		return fmt.Errorf("last seen and endpoints: %w", err)
	}

	mergePeers(o.stats.Data.LastSeen, proto0LastSeen)
	mergePeers(o.stats.Data.Endpoints, proto0Endpoints)

	return nil
}
