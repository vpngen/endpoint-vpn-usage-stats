package main

/*
func TestWgTransfer(t *testing.T) {
	testData := `qvZ/LwkLJGOKA717Lz2N7X6MDxp6rMXR3/3CcJQaZEY=	0	0
BRVNwWdB4JDrZKI0/mf3e/XXfzq/6mR6bHIBN5WsRjQ=	0	0`
	peerTraffic, err := parseWgTransfer(strings.NewReader(testData))
	if err != nil {
		t.Error(err)
	}

	j, err := json.MarshalIndent(peerTraffic, "", "\t")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(j))
}
*/

/*
func TestWgLatestHandshakes(t *testing.T) {
	testData := `qvZ/LwkLJGOKA717Lz2N7X6MDxp6rMXR3/3CcJQaZEY=	0
BRVNwWdB4JDrZKI0/mf3e/XXfzq/6mR6bHIBN5WsRjQ=	0`
	peerLastSeen, err := parseWgLatestHandshakes(strings.NewReader(testData))
	if err != nil {
		t.Error(err)
	}

	j, err := json.MarshalIndent(peerLastSeen, "", "\t")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(j))
}
*/

/*
func TestWgEndpoints(t *testing.T) {
	testData := `qvZ/LwkLJGOKA717Lz2N7X6MDxp6rMXR3/3CcJQaZEY=	(none)
BRVNwWdB4JDrZKI0/mf3e/XXfzq/6mR6bHIBN5WsRjQ=	(none)`
	peerEndpoints, err := parseWgEndpoints(strings.NewReader(testData))
	if err != nil {
		t.Error(err)
	}

	j, err := json.MarshalIndent(peerEndpoints, "", "\t")
	if err != nil {
		t.Error(err)
	}
	t.Log(string(j))
}
*/
