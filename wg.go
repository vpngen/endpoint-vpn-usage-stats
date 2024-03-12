package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

func wgShow(wgi, c string) (io.Reader, error) {
	cmd := exec.Command("ip", "netns", "exec", "ns"+wgi, "wg", "show", wgi, c)
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func wgShowTransfer(wgi string) (io.Reader, error) {
	return wgShow(wgi, "transfer")
}

//	func parseWgTransfer(reader io.Reader) (peer[traffic], error) {
//		scanner := bufio.NewScanner(reader)
//		peerTraffic := make(peer[traffic])
//		for scanner.Scan() {
//			line := scanner.Text()
//			fields := strings.Fields(line)
//			if len(fields) != 3 {
//				return nil, fmt.Errorf("invalid line: %s", line)
//			}
//			peerTraffic[fields[0]] = map[string]traffic{
//				"wireguard": {
//					Received: fields[1],
//					Sent:     fields[2],
//				},
//			}
//		}
//		if err := scanner.Err(); err != nil {
//			return nil, fmt.Errorf("scanner error: %w", err)
//		}
//		return peerTraffic, nil
//	}

func parseWgTransfer(reader io.Reader) (peer[traffic], error) {
	return parseWg(reader, 3, func(peers peer[traffic], fields []string) {
		peers[fields[0]] = map[string]traffic{
			"wireguard": {
				Received: fields[1],
				Sent:     fields[2],
			},
		}
	})
}

func getWgTransfer(wgi string) (peer[traffic], error) {
	stdout, err := wgShowTransfer(wgi)
	if err != nil {
		return nil, fmt.Errorf("wg show transfer: %w", err)
	}
	peers, err := parseWgTransfer(stdout)
	if err != nil {
		return nil, fmt.Errorf("parse wg transfer: %w", err)
	}
	return peers, nil
}

func wgShowLatestHandshakes(wgi string) (io.Reader, error) {
	return wgShow(wgi, "latest-handshakes")
}

//func parseWgLatestHandshakes(reader io.Reader) (peer[lastSeen], error) {
//	scanner := bufio.NewScanner(reader)
//	peerLastSeen := make(peer[lastSeen])
//	for scanner.Scan() {
//		line := scanner.Text()
//		fields := strings.Fields(line)
//		if len(fields) != 2 {
//			return nil, fmt.Errorf("invalid line: %s", line)
//		}
//		peerLastSeen[fields[0]] = map[string]lastSeen{
//			"wireguard": {
//				Timestamp: fields[1],
//			},
//		}
//	}
//	if err := scanner.Err(); err != nil {
//		return nil, fmt.Errorf("scanner error: %w", err)
//	}
//	return peerLastSeen, nil
//}

func parseWgLatestHandshakes(reader io.Reader) (peer[lastSeen], error) {
	return parseWg(reader, 2, func(peers peer[lastSeen], fields []string) {
		peers[fields[0]] = map[string]lastSeen{
			"wireguard": {
				Timestamp: fields[1],
			},
		}
	})
}

func getWgLatestHandshakes(wgi string) (peer[lastSeen], error) {
	stdout, err := wgShowLatestHandshakes(wgi)
	if err != nil {
		return nil, fmt.Errorf("wg show latest-handshakes: %w", err)
	}
	peers, err := parseWgLatestHandshakes(stdout)
	if err != nil {
		return nil, fmt.Errorf("parse wg latest-handshakes: %w", err)
	}
	return peers, nil
}

func wgShowEndpoints(wgi string) (io.Reader, error) {
	return wgShow(wgi, "endpoints")
}

//func parseWgEndpoints(reader io.Reader) (peer[endpoints], error) {
//	scanner := bufio.NewScanner(reader)
//	peerEndpoints := make(peer[endpoints])
//	for scanner.Scan() {
//		line := scanner.Text()
//		fields := strings.Fields(line)
//		if len(fields) != 2 {
//			return nil, fmt.Errorf("invalid line: %s", line)
//		}
//		peerEndpoints[fields[0]] = map[string]endpoints{
//			"wireguard": {
//				Subnet: fields[1],
//			},
//		}
//	}
//	if err := scanner.Err(); err != nil {
//		return nil, fmt.Errorf("scanner error: %w", err)
//	}
//	return peerEndpoints, nil
//}

func parseWgEndpoints(reader io.Reader) (peer[endpoints], error) {
	return parseWg(reader, 2, func(peers peer[endpoints], fields []string) {
		peers[fields[0]] = map[string]endpoints{
			"wireguard": {
				Subnet: fields[1],
			},
		}
	})
}

func getWgEndpoints(wgi string) (peer[endpoints], error) {
	stdout, err := wgShowEndpoints(wgi)
	if err != nil {
		return nil, fmt.Errorf("wg show endpoints: %w", err)
	}
	peers, err := parseWgEndpoints(stdout)
	if err != nil {
		return nil, fmt.Errorf("parse wg endpoints: %w", err)
	}
	return peers, nil
}

func parseWg[T any](reader io.Reader, nFields int, fieldSetter func(peer[T], []string)) (peer[T], error) {
	scanner := bufio.NewScanner(reader)
	peers := make(peer[T])
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != nFields {
			return nil, fmt.Errorf("invalid line: %s", line)
		}
		fieldSetter(peers, fields)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}
	return peers, nil
}
