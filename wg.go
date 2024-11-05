package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func getWgPeers(wgi string) ([]wgtypes.Peer, error) {
	wgc, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl new: %w", err)
	}

	device, err := wgc.Device(wgi)
	if err != nil {
		return nil, fmt.Errorf("wgctrl device: %w", err)
	}

	return device.Peers, nil
}

func getWgTransfer(p []wgtypes.Peer) peer[traffic] {
	peers := make(peer[traffic])
	for _, peer := range p {
		peers[peer.PublicKey.String()] = map[string]traffic{
			protoWireguard: {
				Received: fmt.Sprintf("%d", peer.ReceiveBytes),
				Sent:     fmt.Sprintf("%d", peer.TransmitBytes),
			},
		}
	}

	return peers
}

func getWgLatestHandshakes(p []wgtypes.Peer) peer[lastSeen] {
	peers := make(peer[lastSeen])
	for _, peer := range p {
		if peer.LastHandshakeTime.IsZero() {
			continue
		}

		peers[peer.PublicKey.String()] = map[string]lastSeen{
			protoWireguard: {
				Timestamp: fmt.Sprintf("%d", peer.LastHandshakeTime.Unix()),
			},
		}
	}

	return peers
}

func getWgEndpoints(p []wgtypes.Peer) peer[endpoints] {
	peers := make(peer[endpoints])
	for _, peer := range p {
		if peer.Endpoint == nil {
			continue
		}

		subnet, err := ipToSubnet(peer.Endpoint.String())
		if err != nil {
			debugLog("get subnet from ip: %w", err)

			continue
		}

		peers[peer.PublicKey.String()] = map[string]endpoints{
			protoWireguard: {
				Subnet: subnet,
			},
		}
	}

	return peers
}

func getOutlineSSPortAndPublicIP(myFS fs.FS, filePath string) (string, string, error) {
	file, err := myFS.Open(filePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open file: %w", err)
	}

	defer file.Close()

	var (
		addr string
		port string
	)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "OUTLINE_SS_PORT="):
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				port = parts[1]
			}
		case strings.HasPrefix(line, "EXT_IP="):
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				addr = parts[1]
			}
		}

		if port != "" && addr != "" {
			return port, addr, nil
		}
	}

	if err = scanner.Err(); err != nil {
		return "", "", fmt.Errorf("scanner error: %w", err)
	}

	return "", "", fmt.Errorf("OUTLINE_SS_PORT not found in file")
}
