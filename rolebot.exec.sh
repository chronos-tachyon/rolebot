#!/bin/bash
set -eu -o pipefail
export HOME=~
export PATH="${HOME}/bin:${HOME}/go/bin:${HOME}/goroot/bin:/usr/local/bin:/usr/bin:/bin"
cd
exec rolebot -logfile logs/rolebot.log -tokenfile token -statefile state
