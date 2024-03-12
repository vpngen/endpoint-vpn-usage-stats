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
