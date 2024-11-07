package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"

	statsService "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func getProto0LastSeenAndEndpoints(myFS fs.FS, wgi string) (peer[lastSeen], peer[endpoints], error) {
	file, err := myFS.Open(fmt.Sprintf("opt/xray-%s/authdb.log", wgi))
	if err != nil {
		return nil, nil, fmt.Errorf("open authdb: %w", err)
	}

	defer file.Close()

	ls, ep, err := parseProto0AuthDBLastSeenAndEndpoints(file)
	if err != nil {
		return nil, nil, fmt.Errorf("parse proto0 last seen and endpoints: %w", err)
	}

	return ls, ep, nil
}

func getProto0Traffic() (peer[traffic], error) {
	cmdConn, err := grpc.NewClient("127.0.0.1:10444", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("new grpc client: %w", err)
	}

	c := statsService.NewStatsServiceClient(cmdConn)

	resp, err := c.QueryStats(context.Background(), &statsService.QueryStatsRequest{
		Pattern: "user",
		Reset_:  false, // reset traffic data everytime
	})
	if err != nil {
		return nil, fmt.Errorf("query stats: %w", err)
	}

	peers := make(peer[traffic])

	for _, s := range resp.GetStat() {
		a := strings.Split(s.GetName(), ">>>")
		if len(a) != 4 {
			debugLog("invalid field count:", len(a))

			continue
		}

		if a[0] != "user" || a[2] != "traffic" {
			debugLog("invalid field:", a[0], a[2])

			continue
		}

		if _, ok := peers[a[1]]; !ok {
			peers[a[1]] = make(map[string]traffic)
		}

		x := peers[a[1]][protoProto0]

		switch a[3] {
		case "uplink":
			x.Sent = strconv.FormatInt(s.GetValue(), 10)

		case "downlink":
			x.Received = strconv.FormatInt(s.GetValue(), 10)

		default:
			debugLog("invalid field 3:", a[3])
		}

		peers[a[1]][protoProto0] = x

	}

	return peers, nil
}

func parseProto0AuthDBLastSeenAndEndpoints(reader io.Reader) (peer[lastSeen], peer[endpoints], error) {
	ls := make(peer[lastSeen])
	ep := make(peer[endpoints])

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, nil, fmt.Errorf("invalid line: %q", line)
		}

		pub := strings.ReplaceAll(strings.ReplaceAll(fields[0], "-", "+"), "_", "/")
		if _, err := base64.StdEncoding.DecodeString(pub); err != nil {
			fmt.Fprintf(os.Stderr, "b64std decode %q: %s", fields[0], err)

			continue
		}

		subnet, err := ipToSubnet(fields[2])
		if err != nil {
			return nil, nil, fmt.Errorf("get subnet from ip: %w", err)
		}

		ls[pub] = map[string]lastSeen{protoProto0: {Timestamp: fields[3]}}
		ep[pub] = map[string]endpoints{protoProto0: {Subnet: subnet}}
	}
	if scanner.Err() != nil {
		return nil, nil, fmt.Errorf("scanner error: %w", scanner.Err())
	}

	return ls, ep, nil
}
