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

	metrics interface {
		traffic | lastSeen | endpoints
	}

	// <protoname>: {
	// 	<traffic | lastSeen | endpoints>: <value>
	// }
	proto[T metrics] map[string]T

	// {
	// 	<username>: {
	// 		<protoname>: {
	// 			<traffic | lastSeen | endpoints>: <value>
	// 		}
	// 	}
	// }
	peer[T metrics] map[string]proto[T]

	// aggregated[<protoname>] is a map of aggregated flag.
	// if aggregated flag is 0, the protocol traffic is only interactively.
	// if aggregated flag is 1, the protocol traffic is aggregated.
	aggregated map[string]int

	data struct {
		Aggregated aggregated      `json:"aggregated"`
		Traffic    peer[traffic]   `json:"traffic"`
		LastSeen   peer[lastSeen]  `json:"last-seen"`
		Endpoints  peer[endpoints] `json:"endpoints"`
	}

	stat struct {
		Code      string `json:"code"`
		Data      data   `json:"data"`
		Timestamp string `json:"timestamp"`
	}
)
