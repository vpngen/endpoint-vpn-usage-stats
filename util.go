package main

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
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
