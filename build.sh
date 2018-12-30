#!/bin/bash
set -eu -o pipefail
set -x
export GO111MODULE=on
go build ./cmd/rolebot
