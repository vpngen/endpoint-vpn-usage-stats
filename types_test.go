package main

import (
	"encoding/json"
	"testing"
)

func Test_mergePeers(t *testing.T) {
	var peersA, peersB peer[traffic]
	peersA = map[string]proto[traffic]{
		"peerA": {
			"protoA": {
				Received: "1",
				Sent:     "2",
			},
		},
		"peerB": {
			"protoA": {
				Received: "5",
				Sent:     "6",
			},
		},
	}
	peersB = map[string]proto[traffic]{
		"peerA": {
			"protoB": {
				Received: "11",
				Sent:     "12",
			},
		},
		"peerB": {
			"protoB": {
				Received: "15",
				Sent:     "16",
			},
		},
	}

	merged := mergePeers(peersA, peersB)
	j, err := json.MarshalIndent(merged, "", "\t")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(j))
}
