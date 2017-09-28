#!/bin/bash
set -eu
cd ~/.rolebot
export PATH="${HOME}/go/bin:${PATH}"
nohup bash -c '( exec setsid rolebot -tokenfile=token -statefile=state ) >>log 2>&1 &' </dev/null >/dev/null 2>&1
