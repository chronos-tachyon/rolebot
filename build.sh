#!/bin/bash
set -eu -o pipefail
set -x
vgo build ./cmd/rolebot
vgo build ./cmd/chanbot
