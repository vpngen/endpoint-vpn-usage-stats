package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

func getOutlinePortFromWgQuick(myFS fs.FS, wgi string) (string, string, error) {
	filePath := fmt.Sprintf("etc/wg-quick-ns.env.%s", wgi)

	port, addr, err := getOutlineSSPortAndPublicIP(myFS, filePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to get OUTLINE_SS_PORT: %w", err)
	}

	return port, addr, nil
}

// var outlineTrafficRE = regexp.MustCompile(`shadowsocks_data_bytes\{access_key="(\S+)",dir="(c[<>]p)",proto="(?:tcp|udp)"} (\d\.\d+e\+\d{2})`)
func parseOutlineTraffic(reader io.Reader) (peer[traffic], error) {
	peerTrafficMap := make(map[string]struct{ sent, received int })
	// Decode the metrics
	decoder := expfmt.NewDecoder(reader, expfmt.OpenMetricsType)

	for {
		var mf io_prometheus_client.MetricFamily
		if err := decoder.Decode(&mf); err != nil {
			if err == io.EOF {
				break
			}

			return nil, fmt.Errorf("decode metrics: %w", err)
		}

		if mf.GetName() == "shadowsocks_data_bytes" {
			for _, m := range mf.GetMetric() {
				labels := m.GetLabel()
				var (
					accessKey string
					dir       string
				)

				for _, l := range labels {
					switch l.GetName() {
					case "access_key":
						accessKey = l.GetValue()
					case "dir":
						dir = l.GetValue()
					}
				}

				if accessKey == "" || dir == "" {
					continue
				}

				accessKey = strings.ReplaceAll(strings.ReplaceAll(accessKey, "-", "+"), "_", "/")

				count := m.GetCounter().GetValue()

				trfc, ok := peerTrafficMap[accessKey]
				if !ok {
					trfc = struct{ sent, received int }{}
				}

				switch dir {
				case "c<p":
					trfc.received += int(count)
				case "c>p":
					trfc.sent += int(count)
				default:
					continue
				}

				peerTrafficMap[accessKey] = trfc
			}
		}
	}

	peers := make(peer[traffic])
	for k, v := range peerTrafficMap {
		peers[k] = map[string]traffic{protoOutline: {Sent: strconv.Itoa(v.sent), Received: strconv.Itoa(v.received)}}
	}

	return peers, nil
}

// getOutlineTraffic - get outline traffic from metrics endpoint,
// return common and loopback traffic separately.
func getOutlineTraffic(port string) (peer[traffic], error) {
	// Create an HTTP client with a timeout
	client := &http.Client{
		Timeout: 20 * time.Second, // Set the timeout to 3 seconds
	}

	// Construct the URL
	url := fmt.Sprintf("http://127.0.0.1:%s/metrics", port)

	// Make the GET request
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET request failed: %w", err)
	}

	defer resp.Body.Close()

	// Check for HTTP status errors
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	peers, err := parseOutlineTraffic(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse outline traffic: %w", err)
	}

	return peers, nil
}

func getOutlineLastSeenAndEndpoints(myFS fs.FS, wgi string, addr string) (peer[lastSeen], peer[lastSeen], peer[endpoints], error) {
	file, err := myFS.Open(fmt.Sprintf("opt/outline-ss-%s/authdb.log", wgi))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open authdb: %w", err)
	}

	defer file.Close()

	skip := make([]string, 0, 3)
	subnet, err := ipToSubnet(addr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get subnet from ip: %w", err)
	}

	skip = append(skip, subnet)

	subnet, err = ipToSubnet("127.0.0.1")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get subnet from ip: %w", err)
	}

	skip = append(skip, subnet)

	subnet, err = ipToSubnet("::1")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get subnet from ip: %w", err)
	}

	skip = append(skip, subnet)

	ls, lsp, ep, err := parseOutlineAuthDBLastSeenAndEndpoints(file, skip)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse outline last seen and endpoints: %w", err)
	}

	return ls, lsp, ep, nil
}

func assembleOLCEndpoints(cloakEndpoints map[string]string, uidMap map[string]string) (peer[endpoints], error) {
	peers := make(peer[endpoints])

	for uid, key := range uidMap {
		if subnet, ok := cloakEndpoints[uid]; ok {
			peers[key] = map[string]endpoints{protoOutlineOverCloak: {Subnet: subnet}}
		}
	}

	return peers, nil
}

func parseOutlineAuthDBLastSeenAndEndpoints(reader io.Reader, skip []string) (peer[lastSeen], peer[lastSeen], peer[endpoints], error) {
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

		pub := strings.ReplaceAll(strings.ReplaceAll(fields[0], "-", "+"), "_", "/")
		if _, err := base64.StdEncoding.DecodeString(pub); err != nil {
			fmt.Fprintf(os.Stderr, "b64std decode %q: %s", fields[0], err)

			continue
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
