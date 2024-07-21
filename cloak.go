package main

import (
	"bufio"
	"fmt"
	"io"
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
