package main

import (
	"bufio"
	"fmt"
	"os"
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

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading file: %w", err)
	}

	return "", fmt.Errorf("OUTLINE_SS_PORT not found in file")
}
