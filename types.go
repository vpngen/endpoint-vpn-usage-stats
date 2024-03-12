package main

type (
	traffic struct {
		Received string `json:"received"`
		Sent     string `json:"sent"`
	}

	lastSeen struct {
		Timestamp string `json:"timestamp"`
	}

	endpoints struct {
		Subnet string `json:"subnet"`
	}

	proto[T any] map[string]T

	peer[T any] map[string]proto[T]

	aggregated map[string]int

	data struct {
		Aggregated aggregated      `json:"aggregated"`
		Traffic    peer[traffic]   `json:"traffic"`
		LastSeen   peer[lastSeen]  `json:"last-seen"`
		Endpoints  peer[endpoints] `json:"endpoints"`
	}

	stat struct {
		Code int  `json:"code"`
		Data data `json:"data"`
	}
)

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
