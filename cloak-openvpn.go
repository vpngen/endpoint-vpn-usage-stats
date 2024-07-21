package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// getOVCPeerMaps - mapping
// [common name] -> wg public key.
// [cloak uid] -> wg public key.
func getOVCPeerMaps(myFS fs.FS, path string, list []fs.DirEntry) (map[string]string, map[string]string, error) {
	cnMap := make(map[string]string)
	uidMap := make(map[string]string)

	for _, entry := range list {
		key, uid, err := readOVCMappingFile(myFS, path, entry)
		if err != nil {
			// fmt.Fprintf(os.Stderr, "read openvpn ccd file: %s\n", err)

			continue
		}

		if key == "" || uid == "" {
			continue
		}

		cnMap[entry.Name()] = key
		uidMap[uid] = key
	}

	return cnMap, uidMap, nil
}

// readOVCMappingFile - read openvpn ccd file and return mapping
// [wg public key] , uid.
func readOVCMappingFile(myFS fs.FS, path string, entry fs.DirEntry) (string, string, error) {
	f, err := myFS.Open(filepath.Join(path, entry.Name()))
	if err != nil {
		return "", "", fmt.Errorf("open file: %w", err)
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()

		if !strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(strings.TrimPrefix(line, "#"), " ")
		if len(parts) != 2 {
			// return "", "", fmt.Errorf("invalid line: %q", line)

			continue
		}

		// wg public key -> uid
		return parts[0], parts[1], nil
	}

	if err := scanner.Err(); err != nil {
		return "", "", fmt.Errorf("scan file: %w", err)
	}

	return "", "", fmt.Errorf("no line found")
}

// extractOpenVPNStatus - extract openvpn status from reader,
// ussually from "/opt/openvpn-%s/status.log".
// Status only onlines, not offline.
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

// parseOpenVPNStatus - parse openvpn status from data, return map of openvpn status.
func parseOpenVPNStatus(data []byte, peerMap map[string]string) (map[string]openVPNStatus, error) {
	statuses := make(map[string]openVPNStatus)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Split(line, ",")
		if len(fields) != 5 {
			fmt.Fprintf(os.Stderr, "invalid line: %q\n", line)

			continue
		}

		statuses[peerMap[fields[0]]] = openVPNStatus{
			commonName:     fields[0],
			realAddress:    fields[1],
			bytesReceived:  fields[2],
			bytesSent:      fields[3],
			connectedSince: fields[4],
		}
	}

	return statuses, nil
}

// read "/opt/openvpn-%s/status.log" and extract openvpn status
// read "grep -rH ^# /opt/openvpn-%s/ccd/" and extract openvpn peers
func getOpenVPNStatus(statusR io.Reader, cnMap map[string]string) (map[string]openVPNStatus, error) {
	status, err := extractOpenVPNStatus(statusR)
	if err != nil {
		return nil, fmt.Errorf("extract openvpn status: %w", err)
	}

	statusMap, err := parseOpenVPNStatus(status, cnMap)
	if err != nil {
		return nil, fmt.Errorf("parse openvpn status: %w", err)
	}

	return statusMap, nil
}

// assembleOpenVPNTraffic - assemble openvpn traffic from openvpn status.
func assembleOpenVPNTraffic(status map[string]openVPNStatus) peer[traffic] {
	peers := make(peer[traffic])

	for k, s := range status {
		peers[k] = map[string]traffic{
			protoOpenVPNOverCloak: {
				Received: s.bytesReceived,
				Sent:     s.bytesSent,
			},
		}
	}

	return peers
}

// assembleOpenVPNLastSeen - assemble openvpn last seen from openvpn status.
func assembleOpenVPNLastSeen(status map[string]openVPNStatus) peer[lastSeen] {
	peers := make(peer[lastSeen])
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	for _, s := range status {
		peers[s.commonName] = map[string]lastSeen{protoOpenVPNOverCloak: {Timestamp: ts}}
	}

	return peers
}

func assembleOVCEndpoints(cloakEndpoints map[string]string, uidMap map[string]string, status map[string]openVPNStatus) (peer[endpoints], error) {
	peers := make(peer[endpoints])

	for uid, key := range uidMap {
		if subnet, ok := cloakEndpoints[uid]; ok {
			if _, ok := status[key]; ok {
				peers[key] = map[string]endpoints{protoOpenVPNOverCloak: {Subnet: subnet}}
			}
		}
	}

	return peers, nil
}
