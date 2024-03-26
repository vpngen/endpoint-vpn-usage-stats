package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func getOutlinePortFromWgQuick(wgi string) (string, error) {
	filePath := fmt.Sprintf("/etc/wg-quick-ns.env.%s", wgi)
	port, err := getOutlineSSPort(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to get OUTLINE_SS_PORT: %w", err)
	}
	return port, nil
}

func getOutlineSSPort(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "OUTLINE_SS_PORT=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return parts[1], nil
			}
			break
		}
	}
	if err = scanner.Err(); err != nil {
		return "", fmt.Errorf("scanner error: %w", err)
	}
	return "", fmt.Errorf("OUTLINE_SS_PORT not found in file")
}

var outlineTrafficRE = regexp.MustCompile(`shadowsocks_data_bytes\{access_key="(\S+)",dir="(c[<>]p)",proto="(?:tcp|udp)"} (\d\.\d+e\+\d{2})`)

func parseOutlineTraffic(reader io.Reader) (peer[traffic], error) {
	scanner := bufio.NewScanner(reader)
	peerTrafficMap := make(map[string]struct{ sent, received int })
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "shadowsocks_data_bytes") {
			continue
		}
		match := outlineTrafficRE.FindStringSubmatch(line)
		if len(match) == 0 {
			continue
		}
		if len(match) != 4 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		peerName := match[1]
		side := match[2]
		bytesSent, err := strconv.ParseFloat(match[3], 64)
		if err != nil {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		trfc, ok := peerTrafficMap[peerName]
		if !ok {
			trfc = struct{ sent, received int }{}
		}
		switch side {
		case "c<p":
			trfc.received += int(bytesSent)
		case "c>p":
			trfc.sent += int(bytesSent)
		default:
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		peerTrafficMap[peerName] = trfc
	}
	if scanner.Err() != nil {
		return nil, fmt.Errorf("scanner error: %w", scanner.Err())
	}
	peers := make(peer[traffic])
	for k, v := range peerTrafficMap {
		peers[k] = map[string]traffic{"outline-ss": {Sent: strconv.Itoa(v.sent), Received: strconv.Itoa(v.received)}}
	}
	return peers, nil
}

func getOutlineTraffic(wgi string) (peer[traffic], error) {
	port, err := getOutlinePortFromWgQuick(wgi)
	if err != nil {
		return nil, fmt.Errorf("get outline port: %w", err)
	}
	stdout, err := runcmd("ip", "netns", "exec", "ns"+wgi, "curl", "-s", "--max-time", "3", fmt.Sprintf("http://127.0.0.1:%s/metrics", port))
	if err != nil {
		return nil, fmt.Errorf("runcmd: %w", err)
	}
	peers, err := parseOutlineTraffic(stdout)
	if err != nil {
		return nil, fmt.Errorf("parse outline traffic: %w", err)
	}
	return peers, nil
}

func parseOutlineLastSeenAndEndpoints(reader io.Reader) (peer[lastSeen], peer[endpoints], error) {
	scanner := bufio.NewScanner(reader)
	ls := make(peer[lastSeen])
	ep := make(peer[endpoints])
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, nil, fmt.Errorf("invalid line: %q", line)
		}
		ls[fields[0]] = map[string]lastSeen{"outline-ss": {Timestamp: fields[3]}}
		ep[fields[0]] = map[string]endpoints{"outline-ss": {Subnet: fields[2]}}
	}
	if scanner.Err() != nil {
		return nil, nil, fmt.Errorf("scanner error: %w", scanner.Err())
	}
	return ls, ep, nil
}

func getOutlineLastSeenAndEndpoints(wgi string) (peer[lastSeen], peer[endpoints], error) {
	file, err := os.Open(fmt.Sprintf("/opt/outline-ss-%s/authdb.log", wgi))
	if err != nil {
		return nil, nil, fmt.Errorf("open authdb: %w", err)
	}
	defer file.Close()
	ls, ep, err := parseOutlineLastSeenAndEndpoints(file)
	if err != nil {
		return nil, nil, fmt.Errorf("parse outline last seen and endpoints: %w", err)
	}
	return ls, ep, nil
}
