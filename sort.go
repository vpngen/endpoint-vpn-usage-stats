package main

import (
	"bufio"
	"io"
	"sort"
	"strings"
)

// sortFirstField is equivalent to `sort -k 1,1`
func sortFirstField(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	var lines []string

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sort.Slice(lines, func(i, j int) bool {
		return strings.Fields(lines[i])[0] < strings.Fields(lines[j])[0]
	})

	return lines, nil
}

// sortFirstFieldUnique is equivalent to `sort -u -k 1,1`
func sortFirstFieldUnique(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	linesMap := make(map[string]struct{})
	var lines []string

	for scanner.Scan() {
		line := scanner.Text()
		if _, exists := linesMap[line]; !exists {
			linesMap[line] = struct{}{}
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sort.Slice(lines, func(i, j int) bool {
		return strings.Fields(lines[i])[0] < strings.Fields(lines[j])[0]
	})

	return lines, nil
}
