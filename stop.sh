#!/bin/bash
set -eu
pkill -P 1 -x rolebot
echo -n "killing..."
while pgrep -P 1 -x rolebot &>/dev/null; do
  sleep 1
  echo -n .
done
echo " done"
