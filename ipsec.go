package main

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

func parseIpsecSecrets(reader io.Reader) (map[string]string, error) {
	username2peer := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 6 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		username2peer[strings.Replace(fields[0], `"`, "", -1)] = strings.TrimPrefix(fields[5], "#")
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}
	return username2peer, nil
}

func parseIpsec[T any](reader io.Reader, nFields int, fieldSetter func(peer[T], []string)) (peer[T], error) {
	scanner := bufio.NewScanner(reader)
	//skip header
	scanner.Scan()
	scanner.Scan()
	peers := make(peer[T])
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != nFields {
			return nil, fmt.Errorf("invalid line: %q", line)
		}
		fieldSetter(peers, fields)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}
	return peers, nil
}

func parseIpsecTraffic(reader io.Reader, username2peer map[string]string) (peer[traffic], error) {
	return parseIpsec(reader, 5, func(peers peer[traffic], fields []string) {
		peers[username2peer[fields[0]]] = map[string]traffic{
			"ipsec": {
				Received: fields[2],
				Sent:     fields[4],
			},
		}
	})
}

func parseIpsecEndpoints(reader io.Reader, username2peer map[string]string) (peer[endpoints], error) {
	return parseIpsec(reader, 3, func(peers peer[endpoints], fields []string) {
		peers[username2peer[fields[0]]] = map[string]endpoints{
			"ipsec": {
				Subnet: fields[2],
			},
		}
	})
}

func parseIpsecLastSeen(username2peer map[string]string) peer[lastSeen] {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	peers := make(peer[lastSeen])
	for _, p := range username2peer {
		peers[p] = map[string]lastSeen{"ipsec": {Timestamp: ts}}
	}
	return peers
}

func getIpsecTraffic(wgi string, username2peer map[string]string) (peer[traffic], error) {
	stdout, err := runcmd("ip", "netns", "exec", "ns"+wgi, "accel-cmd", "-4", "-t", "3", "show", "sessions", "username,rx-bytes-raw,tx-bytes-raw")
	if err != nil {
		return nil, fmt.Errorf("accel-cmd: %w", err)
	}
	peers, err := parseIpsecTraffic(stdout, username2peer)
	if err != nil {
		return nil, fmt.Errorf("parse accel-cmd: %w", err)
	}
	return peers, nil
}

func getIpsecEndpoints(wgi string, username2peer map[string]string) (peer[endpoints], error) {
	stdout, err := runcmd("ip", "netns", "exec", "ns"+wgi, "accel-cmd", "-4", "-t", "3", "show", "sessions", "username,subnet")
	if err != nil {
		return nil, fmt.Errorf("accel-cmd: %w", err)
	}
	peers, err := parseIpsecEndpoints(stdout, username2peer)
	if err != nil {
		return nil, fmt.Errorf("parse accel-cmd: %w", err)
	}
	return peers, nil
}
