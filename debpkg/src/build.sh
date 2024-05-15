#!/bin/sh

set -e

export CGO_ENABLED=0

go build -C endpoint-vpn-usage-stats -o ../bin/stats

go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest

nfpm package --config "endpoint-vpn-usage-stats/debpkg/nfpm.yaml" --target "${SHARED_BASE}/pkg" --packager deb

chown "${USER_UID}:${USER_UID}" "${SHARED_BASE}/pkg/"*.deb

