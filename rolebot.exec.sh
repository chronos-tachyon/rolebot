#!/bin/bash
set -eu -o pipefail
export HOME=~
export PATH="${HOME}/bin:${HOME}/.local/bin:${HOME}/go/bin:${HOME}/goroot/bin:/usr/local/bin:/usr/bin:/bin"
cd
exec rolebot --log-file=logs/rolebot.json --tokenfile=token --statefile=state
