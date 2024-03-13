package main

import (
	"bytes"
	"io"
	"os/exec"
)

func runcmd(command string, args ...string) (io.Reader, error) {
	cmd := exec.Command(command, args...)
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func mergePeers[T any](peersA, peersB peer[T]) peer[T] {
	for peerName, protos := range peersB {
		if existing, ok := peersA[peerName]; ok {
			for protoName, v := range protos {
				existing[protoName] = v
			}
		} else {
			peersA[peerName] = protos
		}
	}
	return peersA
}
