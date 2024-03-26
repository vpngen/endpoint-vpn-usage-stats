package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

func getOpenVPNPeerMap(reader io.Reader) (map[string]string, error) {
	scanner := bufio.NewScanner(reader)
	m := make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		tmp := strings.Split(line, ":#")
		if len(tmp) != 2 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		right := strings.Split(tmp[1], " ")
		if len(right) != 2 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		m[right[0]] = right[1]
	}
	return m, nil
}

func extractOpenVPNStatus(reader io.Reader) ([]byte, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		header := "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since\n"
		idx := bytes.Index(data, []byte(header))
		if idx == -1 {
			return 0, nil, fmt.Errorf("%q not found", header)
		}
		start := idx + len(header)
		footer := "ROUTING TABLE"
		idx = bytes.Index(data[start:], []byte(footer))
		if idx == -1 {
			return 0, nil, fmt.Errorf("%q not found", footer)
		}
		end := start + idx
		return len(data), data[start:end], nil
	})
	if !scanner.Scan() {
		return nil, scanner.Err()
	}
	return scanner.Bytes(), nil
}

type openVPNStatus struct {
	commonName     string
	realAddress    string
	bytesReceived  string
	bytesSent      string
	connectedSince string
}

func parseOpenVPNStatus(data []byte, peerMap map[string]string) (map[string]openVPNStatus, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	statuses := make(map[string]openVPNStatus)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ",")
		if len(fields) != 5 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		status := openVPNStatus{
			commonName:     fields[0],
			realAddress:    fields[1],
			bytesReceived:  fields[2],
			bytesSent:      fields[3],
			connectedSince: fields[4],
		}
		statuses[peerMap[status.commonName]] = status
	}
	return statuses, nil
}

func getOpenVPNStatus(statusR, peersR io.Reader) (map[string]openVPNStatus, error) {
	status, err := extractOpenVPNStatus(statusR)
	if err != nil {
		return nil, fmt.Errorf("extract openvpn status: %w", err)
	}
	peerMap, err := getOpenVPNPeerMap(peersR)
	if err != nil {
		return nil, fmt.Errorf("get openvpn peer map: %w", err)
	}
	statusMap, err := parseOpenVPNStatus(status, peerMap)
	if err != nil {
		return nil, fmt.Errorf("parse openvpn status: %w", err)
	}
	return statusMap, nil
}

func getOpenVPNTraffic(status map[string]openVPNStatus) peer[traffic] {
	peers := make(peer[traffic])
	for _, s := range status {
		peers[s.commonName] = map[string]traffic{
			"openvpn": {
				Received: s.bytesReceived,
				Sent:     s.bytesSent,
			},
		}
	}
	return peers
}

func getOpenVPNLastSeen(status map[string]openVPNStatus) peer[lastSeen] {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	peers := make(peer[lastSeen])
	for _, s := range status {
		peers[s.commonName] = map[string]lastSeen{"openvpn": {Timestamp: ts}}
	}
	return peers
}

func getOpenVPNEndpoints(authDb io.Reader, status map[string]openVPNStatus) (peer[endpoints], error) {
	scanner := bufio.NewScanner(authDb)
	m := make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		m[fields[0]] = fields[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan authdb: %w", err)
	}
	peers := make(peer[endpoints])
	for k, s := range status {
		peers[s.commonName] = map[string]endpoints{"openvpn": {Subnet: m[k]}}
	}
	return peers, nil
}
