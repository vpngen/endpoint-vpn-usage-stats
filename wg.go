package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func wgShow(wgi, c string) (io.Reader, error) {
	return runcmd("ip", "netns", "exec", "ns"+wgi, "wg", "show", wgi, c)
}

func wgShowTransfer(wgi string) (io.Reader, error) {
	return wgShow(wgi, "transfer")
}

func parseWgTransfer(reader io.Reader) (peer[traffic], error) {
	return parseWg(reader, 3, func(peers peer[traffic], fields []string) error {
		peers[fields[0]] = map[string]traffic{
			"wireguard": {
				Received: fields[1],
				Sent:     fields[2],
			},
		}
		return nil
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

func parseWgLatestHandshakes(reader io.Reader) (peer[lastSeen], error) {
	return parseWg(reader, 2, func(peers peer[lastSeen], fields []string) error {
		peers[fields[0]] = map[string]lastSeen{
			"wireguard": {
				Timestamp: fields[1],
			},
		}
		return nil
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

func parseWgEndpoints(reader io.Reader) (peer[endpoints], error) {
	return parseWg(reader, 2, func(peers peer[endpoints], fields []string) error {
		if fields[1] == "(none)" {
			return nil
		}
		subnet, err := get24SubnetFromIP(fields[1])
		if err != nil {
			return fmt.Errorf("get subnet from ip: %w", err)
		}
		peers[fields[0]] = map[string]endpoints{
			"wireguard": {
				Subnet: subnet,
			},
		}
		return nil
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

func parseWg[T any](reader io.Reader, nFields int, fieldSetter func(peer[T], []string) error) (peer[T], error) {
	scanner := bufio.NewScanner(reader)
	peers := make(peer[T])
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != nFields {
			return nil, fmt.Errorf("invalid line: %s", line)
		}
		if err := fieldSetter(peers, fields); err != nil {
			return nil, fmt.Errorf("field setter: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}
	return peers, nil
}
