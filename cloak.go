package main

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"strings"
)

func getCloakEndpointsMap(o *appOptions) (map[string]string, error) {
	authDbFile, err := o.rootFS.Open(fmt.Sprintf("opt/cloak-%s/userinfo/userauthdb.log", o.wgi))
	if err != nil {
		return nil, fmt.Errorf("openvpn authdb file: %w", err)
	}

	defer authDbFile.Close()

	return parseCloakEndpoints(authDbFile)
}

// parseCloakEndpoints - mapping cloak uid -> ip subnet.
// ussuallly from /opt/cloak-{wgi}/userinfo/userauthdb.log
func parseCloakEndpoints(authDb io.Reader) (map[string]string, error) {
	m := make(map[string]string)

	scanner := bufio.NewScanner(authDb)
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid line: %q", line)
		}

		// uid -> ip
		m[fields[0]] = fields[1]
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan authdb: %w", err)
	}

	endpoints := make(map[string]string)
	for uid, ip := range m {
		subnet, err := ipToSubnet(ip)
		if err != nil {
			return nil, fmt.Errorf("get subnet from ip: %w: %s", err, ip)
		}

		endpoints[uid] = subnet
	}

	return endpoints, nil
}

// getCloakPeerMaps - mapping
// [cloak uid] -> wg public key.
func getCloakPeerMaps(myFS fs.FS, userlist string) (map[string]string, error) {
	uidMap := make(map[string]string)

	f, err := myFS.Open(userlist)
	if err != nil {
		return uidMap, fmt.Errorf("open file: %w", err)
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

		// uid -> wg public key
		uidMap[parts[1]] = parts[0]
	}

	if err := scanner.Err(); err != nil {
		return uidMap, fmt.Errorf("scan file: %w", err)
	}

	return uidMap, nil
}
