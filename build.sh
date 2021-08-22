#!/bin/bash
set -eu -o pipefail
version="$(cat .version || echo devel)"
set -x
go build -ldflags="-X main.appVersion=${version}" ./cmd/rolebot
