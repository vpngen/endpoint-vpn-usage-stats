package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
)

const (
	ipv4CuttedMask = 24
	ipv6CuttedMask = 56
)

func runcmd(command string, args ...string) (io.Reader, error) {
	buf := new(bytes.Buffer)

	cmd := exec.Command(command, args...)
	cmd.Stdout = buf
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run command: %w", err)
	}

	return buf, nil
}

func mergePeers[T metrics](peersA, peersB peer[T]) peer[T] {
	for peerName, protos := range peersB {
		if existing, ok := peersA[peerName]; ok {
			for protoName, v := range protos {
				existing[protoName] = v
			}

			continue
		}

		peersA[peerName] = protos
	}

	return peersA
}

// ipToSubnet - cut the ip to common subnet.
func ipToSubnet(s string) (string, error) {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return "", fmt.Errorf("parse addr:port: %w: %s", err, s)
		}

		ip = ap.Addr()
	}

	bitmask := ipv4CuttedMask
	if ip.Is6() {
		bitmask = ipv6CuttedMask
	}

	prefix, err := ip.Prefix(bitmask)
	if err != nil {
		return "", fmt.Errorf("prefix: %w: %s: %d", err, ip, bitmask)
	}

	return prefix.Masked().String(), nil
}

func parseAuthDBLastSeenAndEndpoints(reader io.Reader, skip []string, b64std bool) (peer[lastSeen], peer[lastSeen], peer[endpoints], error) {
	ls := make(peer[lastSeen])
	lsp := make(peer[lastSeen])
	ep := make(peer[endpoints])

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, nil, nil, fmt.Errorf("invalid line: %q", line)
		}

		pub := fields[0]

		switch b64std {
		case false:
			peerBytes, err := base64.URLEncoding.DecodeString(fields[0])
			if err != nil {
				return nil, nil, nil, fmt.Errorf("b64url decode %q: %w", fields[0], err)
			}

			pub = base64.URLEncoding.EncodeToString(peerBytes)
		default:
			if _, err := base64.StdEncoding.DecodeString(fields[0]); err != nil {
				return nil, nil, nil, fmt.Errorf("b64std decode %q: %w", fields[0], err)
			}

		}

		subnet, err := ipToSubnet(fields[2])
		if err != nil {
			return nil, nil, nil, fmt.Errorf("get subnet from ip: %w", err)
		}

		ignore := false
		for _, s := range skip {
			if subnet == s {
				ignore = true

				lsp[pub] = map[string]lastSeen{protoOutlineOverCloak: {Timestamp: fields[3]}}

				break
			}
		}

		if ignore {
			continue
		}

		ls[pub] = map[string]lastSeen{protoOutline: {Timestamp: fields[3]}}
		ep[pub] = map[string]endpoints{protoOutline: {Subnet: subnet}}
	}
	if scanner.Err() != nil {
		return nil, nil, nil, fmt.Errorf("scanner error: %w", scanner.Err())
	}

	return ls, lsp, ep, nil
}
